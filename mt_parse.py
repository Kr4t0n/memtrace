from optparse import OptionParser
import os

# Default Value, could be modified with load_whitelist
WHITELIST = ['printf', 'vprintf']
# Default Value, could be modified with load_targetlist
TARGETLIST = []


class allocationInfo(object):
    def __init__(self, address, size, stacktrace):
        self.address = address
        self.size = size
        self.stacktrace = stacktrace

    def set_start_line_num(self, start_line_num):
        self.start_line_num = start_line_num

    def address_to_int(self):
        return int(self.address, 16)


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
            if j == len(function_list) - 1:
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


def trace_particular_memory(filename, output_filename, allocation_info):
    fr = open(filename, 'r')
    fw = open(output_filename, 'w')
    address_info = int(allocation_info.address, 16)
    size_info = allocation_info.size

    for line in fr.readlines():
        curLine = line.strip().replace(':', '').split()
        if len(curLine) <= 1:
            # Unexpected blank line
            pass
        elif len(curLine) == 2:
            # Function name line
            fw.write(line)
        elif curLine[1] == 'Load' or curLine[1] == 'Store':
            # Load of store memory operation
            operation_address = int(curLine[3], 16)
            if (operation_address >= address_info and
                    operation_address <= address_info + size_info):
                fw.write(line)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-f', '--file', dest='filename',
                      help='load data from file')
    parser.add_option('-t', '--target', dest='targetlist',
                      help='load function target list')
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

    if allocation_list:
        while True:
            os.system("clear")
            print "Allocation Information :"
            for i in range(len(allocation_list)):
                alloc_info_print = " -[{:>2d}] {}\t{}".format(
                    i + 1,
                    allocation_list[i].address,
                    allocation_list[i].stacktrace.split()[-1])
                print alloc_info_print
            alloc_index = int(raw_input(
                "Select the memory address to trace (0 to exit): "))
            os.system("clear")
            if alloc_index != 0:
                while True:
                    print "{}\t{}".format(
                        allocation_list[alloc_index - 1].address,
                        allocation_list[alloc_index - 1].stacktrace.split()[-1]
                    )
                    print " -[ 1] Show size and full stack trace of allocation"
                    print " -[ 2] Trace memory usage"
                    menu_choice = int(raw_input("(0 to previous menu): "))
                    if menu_choice == 1:
                        print
                        print "Size: {}".format(
                            allocation_list[alloc_index - 1].size)
                        print allocation_list[alloc_index - 1].stacktrace
                    elif menu_choice == 2:
                        print
                        output_filename = str(raw_input("Output filename: "))
                        trace_particular_memory(
                            options.filename,
                            output_filename,
                            allocation_list[alloc_index - 1])
                    else:
                        break
            else:
                break
