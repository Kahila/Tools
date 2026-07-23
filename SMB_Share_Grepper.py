from impacket.smbconnection import SMBConnection, SessionError
from io import BytesIO
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
import threading
from rich.progress import Progress, SpinnerColumn, TextColumn

username = ""
password = ""
domain = ""

RESULTS_FILE = "grep_results.txt"
results_file_lock = threading.Lock()


# Regular-expression patterns to search for
REGEX_PATTERNS = [
    # Add your patterns here.
    r"(?i)password\s*[:=]\s*[^\s]+",
]


# Shares listed here will not be permission-tested or searched.
# Matching is case-insensitive.
SHARE_BLACKLIST = {
    "IPC$",
    "print$",
    "C$",
}


def is_share_blacklisted(share_name):
    """
    Return True when the share is included in SHARE_BLACKLIST.
    """
    blacklist = {
        blacklisted_share.casefold()
        for blacklisted_share in SHARE_BLACKLIST
    }

    return share_name.casefold() in blacklist


def write_grep_results(
    target,
    share_name,
    full_path,
    matches,
):
    """
    Write exact regular-expression matches to the results file.

    A lock prevents multiple worker threads from writing simultaneously.
    """
    unc_path = f"\\\\{target}\\{share_name}{full_path}"

    with results_file_lock:
        with open(
            RESULTS_FILE,
            "a",
            encoding="utf-8",
        ) as output_file:
            output_file.write(
                f"[REGEX MATCH] {unc_path}\n"
            )

            for line_number, regex_match in matches:
                output_file.write(
                    f"    Line {line_number}: "
                    f"{regex_match}\n"
                )

            output_file.write("\n")


def process_host(
    target,
    username,
    password,
    progress,
    domain="",
):
    """
    Connect to a host, enumerate accessible shares, and scan readable files.

    Blacklisted shares are skipped before permission checks or file searches.
    A loader remains visible while the host is being processed.
    """
    conn = None

    task_id = progress.add_task(
        f"Processing {target}",
        total=None,
    )

    try:
        conn = SMBConnection(
            target,
            target,
            timeout=5,
        )

        conn.login(
            username,
            password,
            domain,
        )

        shares = conn.listShares()

        for share in shares:
            share_name = (
                share["shi1_netname"]
                .rstrip("\x00")
            )

            # Skip blacklisted shares completely.
            if is_share_blacklisted(share_name):
                continue

            unc_share = f"\\\\{target}\\{share_name}"

            progress.update(
                task_id,
                description=f"Processing {unc_share}",
            )

            read, write = check_share_permissions(
                conn,
                share_name,
            )

            if read or write:
                progress.console.print(
                    f"{Fore.GREEN}"
                    f"{unc_share}: "
                    f"Read={read}, Write={write}"
                    f"{Style.RESET_ALL}"
                )

            if read:
                list_readable_files(
                    conn=conn,
                    target=target,
                    share_name=share_name,
                    progress=progress,
                    task_id=task_id,
                )

    except Exception:
        return

    finally:
        if conn is not None:
            try:
                conn.logoff()
            except Exception:
                pass

        progress.remove_task(task_id)


def check_share_permissions(
    conn,
    share_name,
):
    """
    Test effective read and write access to an SMB share.
    """
    can_read = False
    can_write = False

    # Test read access.
    try:
        conn.listPath(
            share_name,
            r"\*",
        )
        can_read = True
    except Exception:
        pass

    # Test write access.
    try:
        test_file = "nu11v3c70r_t3st_fi13.txt"
        data = BytesIO(b"Permission Test")

        conn.putFile(
            share_name,
            test_file,
            data.read,
        )

        conn.deleteFile(
            share_name,
            test_file,
        )

        can_write = True

    except Exception:
        pass

    return can_read, can_write


def decode_text(
    data: bytes,
) -> str | None:
    """
    Attempt to decode file contents as text.
    """
    for encoding in (
        "utf-8",
        "utf-16",
        "latin-1",
    ):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue

    return None


def grep_regex_matches(
    text: str,
):
    """
    Return the exact text matched by each configured regular expression.
    """
    matches = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        for pattern in REGEX_PATTERNS:
            regex_match = re.search(
                pattern,
                line,
            )

            if regex_match:
                matches.append(
                    (
                        line_number,
                        regex_match.group(0).strip(),
                    )
                )

                # Record only the first matching pattern for this line.
                break

    return matches


def list_readable_files(
    conn,
    target,
    share_name,
    progress,
    task_id,
    path="\\",
):
    """
    Recursively enumerate and grep readable files.

    Regex matches are written to a file and are not printed.
    """
    try:
        entries = conn.listPath(
            share_name,
            path + "*",
        )
    except Exception:
        return

    for entry in entries:
        name = entry.get_longname()

        if name in (".", ".."):
            continue

        full_path = path + name

        if entry.is_directory():
            list_readable_files(
                conn=conn,
                target=target,
                share_name=share_name,
                progress=progress,
                task_id=task_id,
                path=full_path + "\\",
            )
            continue

        try:
            unc_path = (
                f"\\\\{target}\\"
                f"{share_name}{full_path}"
            )

            progress.update(
                task_id,
                description=f"Grepping {unc_path}",
            )

            buffer = BytesIO()

            conn.getFile(
                share_name,
                full_path,
                buffer.write,
            )

            text = decode_text(
                buffer.getvalue()
            )

            if text is None:
                continue

            matches = grep_regex_matches(text)

            if not matches:
                continue

            write_grep_results(
                target=target,
                share_name=share_name,
                full_path=full_path,
                matches=matches,
            )

        except Exception:
            pass


def load_targets(
    filename: str,
) -> list[str]:
    """
    Load single IP addresses and CIDR ranges from a file.
    """
    targets: list[str] = []

    try:
        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                target = line.strip()

                if not target or target.startswith("#"):
                    continue

                try:
                    network = ip_network(
                        target,
                        strict=False,
                    )

                    for ip in network.hosts():
                        targets.append(str(ip))

                except ValueError:
                    pass

    except OSError:
        pass

    return targets


targets = load_targets("hosts.txt")


# Clear results from the previous scan.
with open(
    RESULTS_FILE,
    "w",
    encoding="utf-8",
) as output_file:
    output_file.write("SMB Regex Grep Results\n")
    output_file.write("=" * 80 + "\n\n")


with Progress(
    SpinnerColumn(),
    TextColumn("{task.description}"),
    transient=True,
    refresh_per_second=10,
) as progress:

    with ThreadPoolExecutor(
        max_workers=50,
    ) as executor:

        futures = {
            executor.submit(
                process_host,
                ip,
                username,
                password,
                progress,
            ): ip
            for ip in targets
        }

        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass