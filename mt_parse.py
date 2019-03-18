from optparse import OptionParser
import os

# Default Value, could be modified with load_whitelist
WHITELIST = ['printf', 'vprintf']
# Default Value, could be modified with load_targetlist
TARGETLIST = []
# Default Value, could be modified with load_modules
MODULES = []
# Default Value, could be modified with load_safelist
SAFELIST = []
# Default Value, could be modified with load_vulnerlist
VULNERLIST = []


class allocationInfo(object):
    def __init__(self, address, size, stacktrace):
        self.address = address
        self.size = size
        self.stacktrace = stacktrace
        self.function_order = []

    def set_start_line_num(self, start_line_num):
        self.start_line_num = start_line_num

    def address_to_int(self):
        return int(self.address, 16)

    def add_function_order(self, function):
        self.function_order.append(function)


def load_whitelist(filename):
    del WHITELIST[:]
    fr = open(filename, 'r')
    for line in fr:
        curLine = line.strip().split()
        WHITELIST.extend(curLine)
    fr.close()


def load_targetlist(filename):
    del TARGETLIST[:]
    fr = open(filename, 'r')
    for line in fr:
        curLine = line.strip().split()
        TARGETLIST.extend(curLine)
    fr.close()


def load_modules(filename):
    del MODULES[:]
    fr = open(filename, 'r')
    for line in fr:
        curLine = line.strip().split()
        MODULES.extend(curLine)
    fr.close()


def load_safelist(filename):
    del SAFELIST[:]
    fr = open(filename, 'r')
    for line in fr:
        curLine = line.strip().split()
        SAFELIST.extend(curLine)
    fr.close()


def load_vulnerlist(filename):
    del VULNERLIST[:]
    fr = open(filename, 'r')
    for line in fr:
        curLine = line.strip().split()
        VULNERLIST.extend(curLine)
    fr.close()


def collect_allocation_info(filename, allocation_list):
    fr = open(filename, 'r')
    line_num = 1
    for line in fr:
        curLine = line.strip().split()
        if (len(curLine) > 5 and curLine[1] == 'Detected' and
                curLine[2] == 'allocation'):
            stacktrace = ''
            while True:
                try:
                    line = fr.next()
                    line_num += 1
                    curLine = line.strip().split()
                    if (len(curLine) > 1 and
                            curLine[1] in ['at', 'by']):
                        stacktrace += ' '.join(curLine[1:]) + '\n'
                    else:
                        break
                except Exception:
                    return

            line = fr.next()
            line_num += 1
            curLine = line.replace(',', '').replace(
                ':', '').strip().split()
            if (len(curLine) > 4 and
                    curLine[1] == 'Address'):
                address = str(curLine[2])
                size = int(curLine[4])
                allocation_list.append(
                    allocationInfo(address, size, stacktrace))
                allocation_list[-1].set_start_line_num(line_num)
        else:
            pass
        line_num += 1
    fr.close()


def filter_allocation_info(allocation_list):
    if allocation_list:
        filter_allocation_list = []
        for i in range(len(allocation_list)):
            stacktrace = allocation_list[i].stacktrace
            function_list = map(lambda x: x.split(' ')[2],
                                stacktrace.split('\n')[:-1])
            for j in range(len(function_list)):
                if function_list[j] in WHITELIST:
                    break
            else:
                filter_allocation_list.append(allocation_list[i])
        return filter_allocation_list
    else:
        return allocation_list


def aim_allocation_info(allocation_list):
    if allocation_list:
        aim_allocation_list = []
        for i in range(len(allocation_list)):
            stacktrace = allocation_list[i].stacktrace
            function_list = map(lambda x: x.split(' ')[2],
                                stacktrace.split('\n')[:-1])
            for j in range(len(function_list)):
                if function_list[j] in TARGETLIST:
                    aim_allocation_list.append(allocation_list[i])
                    break
        return aim_allocation_list
    else:
        return allocation_list


def module_allocation_info(allocation_list):
    if allocation_list:
        module_allocation_list = []
        for i in range(len(allocation_list)):
            stacktrace = allocation_list[i].stacktrace
            module_list = map(lambda x: x.split(' ')[3].split(':')[0][1:],
                              stacktrace.split('\n')[:-1])
            for j in range(len(module_list)):
                if module_list[j] in MODULES:
                    module_allocation_list.append(allocation_list[i])
                    break
        return module_allocation_list
    else:
        return allocation_list


def trace_particular_memory(filename, output_filename, allocation_info):
    fr = open(filename, 'r')
    fw = open(output_filename, 'w')
    address_info = int(allocation_info.address, 16)
    size_info = allocation_info.size

    if allocation_info.function_order:
        del allocation_info.function_order[:]

    # Find first function
    while True:
        line = fr.readline()
        curLine = line.strip().replace(':', '').split()
        if len(curLine) == 2:
            # Function line
            function_line = line
            break
        else:
            continue

    for line in fr:
        curLine = line.strip().replace(':', '').split()
        if len(curLine) <= 1:
            # Unexpected blank line
            continue
        elif len(curLine) == 2:
            # A new function came in
            function_line = line
            continue
        elif curLine[1] in ['Load', 'Store']:
            # Load or Store memory operation
            # Match the operation addresses
            operation_address = int(curLine[3], 16)
            if (operation_address >= address_info and
                    operation_address < address_info + size_info):
                # There is a match, write the operation
                # Check first if we write function name before
                if function_line:
                    fw.write(function_line)
                    allocation_info.add_function_order(
                        function_line.strip().replace(':', '').split()[1])
                    function_line = ""
                fw.write('\t' + ' '.join(line.split()[1:]) + '\n')
            continue
        else:
            continue

    fr.close()
    fw.close()


def menu_show_allocation_list(filename, allocation_list, full_allocation_list):
    while True:
        os.system("clear")
        print "Allocation Information :"
        for i in range(len(allocation_list)):
            alloc_info_print = " -[{:>2d}] {}\t{}".format(
                i + 1,
                allocation_list[i].address,
                allocation_list[i].stacktrace.split()[-1])
            print alloc_info_print

        try:
            alloc_index = int(raw_input(
                "Select the memory address to trace (0 to previous menu): "))
            if alloc_index > len(allocation_list):
                print "Index out of range, please input correct number"
                raw_input("Press ENTER key to continue ...")
            elif alloc_index == 0:
                break
            else:
                menu_show_allocation_info(
                    filename,
                    allocation_list[alloc_index - 1],
                    full_allocation_list)
        except Exception:
            continue


def menu_show_allocation_info(filename, allocation_info, full_allocation_list):
    os.system("clear")
    while True:
        print "{}\t{}".format(
            allocation_info.address,
            allocation_info.stacktrace.split()[-1]
        )
        print " -[ 1] Show size and full stack trace of allocation"
        print " -[ 2] Output memory tracing for this allocation"
        print " -[ 3] Extract Function Execution Order"
        print " -[ 4] Attack Analysis"
        try:
            menu_choice = int(raw_input("(0 to previous menu): "))
            if menu_choice == 1:
                print
                print "Size: {}".format(allocation_info.size)
                print allocation_info.stacktrace
            elif menu_choice == 2:
                print
                output_filename = str(raw_input("Output filename: "))
                trace_particular_memory(
                    filename,
                    output_filename,
                    allocation_info)
                print "Output Memory Tracing File Successfully! \n"
            elif menu_choice == 3:
                if allocation_info.function_order:
                    print allocation_info.function_order
                    print
                else:
                    print "Please Run Option 2 first! \n"
            elif menu_choice == 4:
                attack_analysis_process(
                    filename, allocation_info, full_allocation_list)
            elif menu_choice == 0:
                break
            else:
                print
                continue
        except Exception:
            print
            continue


def attack_analysis_process(filename, allocation_info, full_allocation_list):
    while True:
        os.system("clear")
        print "Attack Analysis Process ..."
        try:
            overflow_offset = int(
                raw_input("Overflow offset (Hex form): "), 16)
            overflow_size = int(
                raw_input("Overflow size (Bytes): "))
        except Exception:
            continue
        overflow_start = int(allocation_info.address, 16) + overflow_offset
        overflow_end = overflow_start + overflow_size
        hex_overflow_start = "0x{:08x}".format(overflow_start)
        hex_overflow_end = "0x{:08x}".format(overflow_end)
        print "Potential corrupted memory interval [{}, {}]".format(
            hex_overflow_start, hex_overflow_end)
        bug_site_func = raw_input("Bug site function: ")
        print
        print "Retrieve bug site function information ..."
        bug_site_occur = bug_site_occur_analysis(filename, bug_site_func)
        print "Analysis influenced corrupted memory structure ..."
        corrupted_allocation_list = influenced_corrupted_memory(
            overflow_start,
            overflow_end,
            full_allocation_list)
        raw_input("Press ENTER key to continue ...")
        print
        print "Attack inferring ..."
        for i in range(len(corrupted_allocation_list)):
            print "Structure {:>2d} - {}".format(
                i + 1,
                corrupted_allocation_list[i].address)
            attack_infer_process(filename,
                                 bug_site_occur,
                                 corrupted_allocation_list[i],
                                 overflow_start,
                                 overflow_end)
        break
    raw_input("Press ENTER key to continue ...")
    os.system("clear")


def bug_site_occur_analysis(filename, bug_site_func):
    fr = open(filename, 'r')
    line_num = 0
    for line in fr:
        line_num += 1
        curLine = line.strip().replace(':', '').split()
        if len(curLine) == 2:
            if bug_site_func == curLine[1]:
                break
            else:
                continue
        else:
            continue

    fr.close()
    return line_num


def influenced_corrupted_memory(overflow_start,
                                overflow_end,
                                full_allocation_list):
    corrupted_allocation_list = []
    for i in range(len(full_allocation_list)):
        start_point = int(full_allocation_list[i].address, 16)
        end_point = start_point + full_allocation_list[i].size
        if (end_point < overflow_start or overflow_end < start_point):
            continue
        else:
            corrupted_allocation_list.append(full_allocation_list[i])

    for i in range(len(corrupted_allocation_list)):
        alloc_info_print = "\t[{:>2d}] {}\t{}".format(
            i + 1,
            corrupted_allocation_list[i].address,
            corrupted_allocation_list[i].stacktrace.split()[-1])
        print alloc_info_print

    return corrupted_allocation_list


def attack_infer_process(filename,
                         bug_site_occur,
                         corrupted_allocation_info,
                         overflow_start,
                         overflow_end):
    try:
        os.mkdir('./{}'.format(bug_site_occur))
    except Exception:
        pass
    write_file_path = '{}/{}.log'.format(
        bug_site_occur,
        corrupted_allocation_info.address)
    print "\tDumping memory tracing file to {} ...".format(write_file_path)
    fr = open(filename, 'r')
    fw = open(write_file_path, 'w')
    if corrupted_allocation_info.function_order:
        del corrupted_allocation_info.function_order[:]

    for i in range(bug_site_occur - 1):
        fr.readline()

    corrupted_start = int(corrupted_allocation_info.address, 16)
    corrupted_end = corrupted_start + corrupted_allocation_info.size
    start_point = max(corrupted_start, overflow_start)
    end_point = min(corrupted_end, overflow_end)

    for line in fr:
        curLine = line.strip().replace(':', '').split()
        if len(curLine) <= 1:
            continue
        elif len(curLine) == 2:
            function_line = line
            continue
        elif curLine[1] in ['Load', 'Store']:
            operation_address = int(curLine[3], 16)
            if (operation_address >= start_point and
                    operation_address <= end_point):
                if function_line:
                    fw.write(function_line)
                    corrupted_allocation_info.add_function_order(
                        function_line.strip().replace(':', '').split()[1])
                    function_line = ""
                fw.write('\t' + ' '.join(line.split()[1:]) + '\n')
            continue
        else:
            continue

    fr.close()
    fw.close()

    print "\tFunctions following up:"
    print u"\t\t{}\n".format(
        u' \u2192 '.join(corrupted_allocation_info.function_order))
    function_safe_vulner_analysis(corrupted_allocation_info.function_order)


def function_safe_vulner_analysis(function_order):
    print "\tFunctions characteristic analysis ..."
    vulner_functions = []
    unknown_functions = []
    for function in function_order:
        if function in SAFELIST:
            continue
        elif function in VULNERLIST:
            vulner_functions.append(function)
        else:
            unknown_functions.append(function)
    print "\tPotential vulnerable functions:"
    if vulner_functions:
        print "\t\t{}".format(", ".join(vulner_functions))
    else:
        print "\t\tNone"
    print "\tUnknoen functions, need further manual analysis:"
    if unknown_functions:
        print "\t\t{}".format(", ".join(unknown_functions))
    else:
        print "\t\tNone"

    if not (vulner_functions or unknown_functions):
        print "\tCurrently safe !"

    print


def menu_function_analysis(filename, allocation_list):
    os.system("clear")
    function_name = raw_input("Type any function name involved :")
    if function_name:
        address_list = function_analysis(filename, function_name)
        print "Potential involved allocation start point :"
        print address_list
        raw_input("Press ENTER key to continue ...")
        potential_allocation_list = search_allocationInfo_with_address(
            address_list, allocation_list)
        menu_show_allocation_list(
            filename, potential_allocation_list, allocation_list)


def function_analysis(filename, function_name):
    fr = open(filename, 'r')
    address_list = []

    for line in fr:
        curLine = line.strip().split()
        if len(curLine) == 2:
            # Function line
            # Match function name
            if curLine[1] == function_name:
                while True:
                    line = fr.next()
                    curLine = line.strip().replace(':', '').split()
                    if len(curLine) > 2:
                        if curLine[1] in ['Load', 'Store']:
                            start_point = int(
                                curLine[3], 16) - int(curLine[7], 16)
                            hex_start_point = "0x{:08x}".format(start_point)
                            if hex_start_point in address_list:
                                pass
                            else:
                                address_list.append(hex_start_point)
                    else:
                        break
            else:
                continue
        else:
            continue

    fr.close()
    return address_list


def search_allocationInfo_with_address(address_list, allocation_list):
    result_allocation_list = []
    for i in range(len(allocation_list)):
        address = allocation_list[i].address
        if address in address_list:
            result_allocation_list.append(allocation_list[i])
        else:
            pass

    return result_allocation_list


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-f', '--file', dest='filename',
                      help='load memory tracing data')
    parser.add_option('-m', '--module', dest='modules',
                      help='load specific allocation module sources from file \
                       to filter (eg. main.c)')
    parser.add_option('-s', '--safe_function', dest='safelist',
                      help='load safe functions from safe list')
    parser.add_option('-t', '--target', dest='targetlist',
                      help='load target allocation function sources from file \
                       to filter (eg. malloc_init)')
    parser.add_option('-v', '--vulnerable_function', dest='vulnerlist',
                      help='load vulnerable functions from vulner list')
    parser.add_option('-w', '--whitelist', dest='whitelist',
                      help='load function white list')
    (options, args) = parser.parse_args()

    allocation_list = []

    if options.filename:
        collect_allocation_info(options.filename, allocation_list)

    if options.whitelist:
        load_whitelist(options.whitelist)
    allocation_list = filter_allocation_info(allocation_list)

    if options.targetlist:
        load_targetlist(options.targetlist)
        allocation_list = aim_allocation_info(allocation_list)

    if options.modules:
        load_modules(options.modules)
        allocation_list = module_allocation_info(allocation_list)

    if options.safelist:
        load_safelist(options.safelist)

    if options.vulnerlist:
        load_vulnerlist(options.vulnerlist)

    if allocation_list:
        while True:
            os.system("clear")
            print " -[ 1] Show Allocation Information List"
            print " -[ 2] Not Sure Specific Allocation"
            try:
                menu_choice = int(raw_input(
                    "Select menu option (0 to exit): "))
                os.system("clear")
                if menu_choice == 1:
                    menu_show_allocation_list(
                        options.filename, allocation_list, allocation_list)
                elif menu_choice == 2:
                    menu_function_analysis(
                        options.filename, allocation_list)
                elif menu_choice == 0:
                    break
                else:
                    continue
            except Exception:
                continue
