# tvc (x86)
The tool for bugs detection in the process of tainted data propagation (based on DBI Intel PIN).

Requirements:
 1. Intel pin-2.13-65163-msvc10-windows (Windows compilation)
 2. Intel pin-2.13-65163-gcc.4.4.7-linux (Linux compilation)


This tool aimed to find bugs in the process of tainted data propagation in machine code (x86 architecture).
Taint analyzer is taken and a little bit modified from this blog:
http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/

<h4>Usage:</h4>

<pre>
pin.exe -t tvc.dll -i &lt;syscalls_list&gt; -o &lt;log_file&gt; -no_dll &lt;1|0&gt; -- &lt;target_app&gt;
-i &lt;syscalls_list&gt; - file that contains syscalls list which process tainted data (PTAL tainted_syscalls.in for example).
-o &lt;log_file&gt; - file to write results.
-no_dll 1 - tvc will not consider code in shared dll.
</pre>
