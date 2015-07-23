# tvc
The tool for bugs detection in the process of tainted data propagation (based on DBI Intel PIN).

Requirements:
 1. Intel pin-2.13-65163-msvc10-windows (Windows compilation)
 2. Intel pin-2.13-65163-gcc.4.4.7-linux (Linux compilation)


This tool aimed to find bugs in the process of tainted data propagation in machine code.

<h4>Usage:</h4>

<pre>
pin.exe -t tvc.dll -i &lt;syscalls list&gt; -o &lt;log file&gt; -no_dll &lt;1|0&gt; -- &lt;target_app&gt;
-i &lt;syscalls list&gt; - file that contains syscalls list which process tainted data (PTAL syscalls.in for example).
-o &lt;log file&gt; - file to write results
-no_dll - if 1 - tvc will not consider code in shared dll.
</pre>
