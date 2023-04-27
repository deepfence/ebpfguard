#!/usr/bin/env python3

import sys
import logging

logging.basicConfig()
log = logging.getLogger(None)
log.setLevel(logging.INFO)


def main():
    try:
        with open("/sys/kernel/security/lsm", "r") as f:
            lsms = f.read().strip().split(",")
    except Exception as e:
        log.error(
            "Couldn't open lsm capabilities pseudo file. Check if your kernel supports lsm."
        )
        sys.exit(-1)

    if "bpf" in lsms:
        log.info("BPF LSM already enabled")
        return

    lsms.append("bpf")

    content = []
    bpf_line = None
    with open("/etc/default/grub") as fd:
        for i, l in enumerate(fd):
            if l.startswith("GRUB_CMDLINE_LINUX="):
                if bpf_line:
                    log.warning(
                        "Multiple GRUB_CMDLINE_LINUX. Only last one takes effect. Check your configuration. This script will modify last occurence only."
                    )
                bpf_line = (i, l)
            else:
                content.append(l)
    idx, effective_grub_cmdline = bpf_line

    if not effective_grub_cmdline:
        log.error("""No line starting with "GRUB_CMDLINE_LINUX=".""")
        sys.exit(-2)

    if "lsm" in effective_grub_cmdline:
        log.warning(
            f"""LSMs explicitly declared in /etc/default/grub GRUB_CMDLINE_LINUX. Edit manually and append bpf value.
        Whole line could look like GRUB_CMDLINE_LINUX="lsm={','.join(lsms)}" """
        )
        sys.exit(-3)

    modified_cmdline = effective_grub_cmdline.lstrip('GRUB_CMDLINE_LINUX="').rstrip('"\n')
    cmdline_lsm = "lsm={}".format(",".join(lsms))
    if modified_cmdline == "":
        modified_cmdline = cmdline_lsm
    else:
        modified_cmdline += " " + cmdline_lsm
    modified_cmdline = 'GRUB_CMDLINE_LINUX="{}"\n'.format(modified_cmdline)

    content.insert(idx, modified_cmdline)

    print("".join(content))


if __name__ == "__main__":
    main()
