set pagination off
set logging file gdb.output
set logging on

# do not stop on signals
handle all nostop pass

# This line is a comment
break __mmap
break __munmap
commands 1 2
    backtrace
    continue
end

continue

# while(1)
#     continue
# end

set logging off
quit