import ida_kernwin
import idautils
import idaapi
import idc


def make_functions_in_range(start_ea, end_ea):
    ea = start_ea
    failed_addrs = []

    while ea < end_ea:
        print("{0:X} - {1:X}".format(ea, end_ea))
        if idc.is_unknown(idc.get_full_flags(ea)):
            func_start = ea
            

            res = idc.add_func(func_start)
            print("res", res)

            if not res or idc.get_func_name(func_start) == '':
                failed_addrs.append(func_start)

            ea = idc.next_head(func_start, end_ea)

        else:
            ea += 1

    if failed_addrs:
        print("Could not create function at:")
        for a in failed_addrs:
            tmp = idc.get_wide_word(a)
            # Skip some bytes which are not functions.
            if tmp != 0xBF00:
                print("  - {0:X}".format(a))

    return failed_addrs


def main():
    start = ida_kernwin.ask_addr(get_screen_ea(), "Start address:")
    if start is None:
        return

    end = ida_kernwin.ask_addr(idc.get_segm_end(start), "End address:")
    if end is None:
        return

    failed = make_functions_in_range(start, end)

if __name__ == "__main__":
    main()
