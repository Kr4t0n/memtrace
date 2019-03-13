from optparse import OptionParser
import os

# Default Value, could be modified with load_whitelist
WHITELIST = ['printf', 'vprintf']
# Default Value, could be modified with load_targetlist
TARGETLIST = []
# Default Value, could be modified with load_modules
MODULES = []


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
                    filename, allocation_list[alloc_index - 1])
        except Exception:
            continue


def menu_show_allocation_info(filename, allocation_info):
    os.system("clear")
    while True:
        print "{}\t{}".format(
            allocation_info.address,
            allocation_info.stacktrace.split()[-1]
        )
        print " -[ 1] Show size and full stack trace of allocation"
        print " -[ 2] Output memory tracing for this allocation"
        print " -[ 3] Extract Function Execution Order"
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
                    print "Please Select Option 2 first! \n"
            elif menu_choice == 0:
                break
            else:
                print
                continue
        except Exception:
            print
            continue


def menu_analysis_function(filename, allocation_list):
    os.system("clear")
    function_name = raw_input("Type any function name involved :")
    if function_name:
        address_list = analysis_function(filename, function_name)
        print "Potential involved allocation start point :"
        print address_list
        raw_input("Press ENTER key to continue ...")
        potential_allocation_list = search_allocationInfo_with_address(
            address_list, allocation_list)
        menu_show_allocation_list(
            filename, potential_allocation_list, allocation_list)


def analysis_function(filename, function_name):
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
    parser.add_option('-t', '--target', dest='targetlist',
                      help='load target allocation function sources from file \
                       to filter (eg. malloc_init)')
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
                    menu_analysis_function(
                        options.filename, allocation_list)
                elif menu_choice == 0:
                    break
                else:
                    continue
            except Exception:
                continue

    # if allocation_list:
    #     while True:
    #         os.system("clear")
    #         print "Allocation Information :"
    #         for i in range(len(allocation_list)):
    #             alloc_info_print = " -[{:>2d}] {}\t{}".format(
    #                 i + 1,
    #                 allocation_list[i].address,
    #                 allocation_list[i].stacktrace.split()[-1])
    #             print alloc_info_print
    #         alloc_index = int(raw_input(
    #             "Select the memory address to trace (0 to exit): "))
    #         os.system("clear")
    #         if alloc_index != 0:
    #             while True:
    #                 print "{}\t{}".format(
    #                     allocation_list[alloc_index - 1].address,
    #                     allocation_list[alloc_index - 1].stacktrace.split()[-1]
    #                 )
    #                 print " -[ 1] Show size and full stack trace of allocation"
    #                 print " -[ 2] Trace memory usage"
    #                 menu_choice = int(raw_input("(0 to previous menu): "))
    #                 if menu_choice == 1:
    #                     print
    #                     print "Size: {}".format(
    #                         allocation_list[alloc_index - 1].size)
    #                     print allocation_list[alloc_index - 1].stacktrace
    #                 elif menu_choice == 2:
    #                     print
    #                     output_filename = str(raw_input("Output filename: "))
    #                     trace_particular_memory(
    #                         options.filename,
    #                         output_filename,
    #                         allocation_list[alloc_index - 1])
    #                 else:
    #                     break
    #         else:
    #             break
