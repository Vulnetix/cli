import subprocess

def flash(elf):
    # enable SWD via openocd and program the board
    subprocess.run(["openocd", "-f", "interface/stlink.cfg", "-c", "program %s verify reset exit" % elf], check=True)
    print("HAL_DBGMCU_EnableDBGStopMode is only compiled in debug builds")
