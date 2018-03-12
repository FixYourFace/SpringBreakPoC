# SpringBreakPoC
I needed a tool to test several different endpoints for the recently disclosed SpringBreak vulnerability (CVE-2017-8046) and couldn't find one, so I threw this together.

# Usage
```
_______  _______  _______ _________ _        _______  ______   _______  _______  _______  _
(  ____ \(  ____ )(  ____ )\__   __/( (    /|(  ____ \(  ___ \ (  ____ )(  ____ \(  ___  )| \    /\
| (    \/| (    )|| (    )|   ) (   |  \  ( || (    \/| (   ) )| (    )|| (    \/| (   ) ||  \  / /
| (_____ | (____)|| (____)|   | |   |   \ | || |      | (__/ / | (____)|| (__    | (___) ||  (_/ /
(_____  )|  _____)|     __)   | |   | (\ \) || | ____ |  __ (  |     __)|  __)   |  ___  ||   _ (
     ) || (      | (\ (      | |   | | \   || | \_  )| (  \ \ | (\ (   | (      | (   ) ||  ( \ \
/\____) || )      | ) \ \_____) (___| )  \  || (___) || )___) )| ) \ \__| (____/\| )   ( ||  /  \
\_______)|/       |/   \__/\_______/|/    )_)(_______)|/ \___/ |/   \__/(_______/|/     \||_/    \/

PoC for CVE-2017-8046. Available commands:
 target <https://host/app/path>
 exec <command to execute on target>
 base64 <on|off> (Toggles base64 encoding of commands (uses bash), default: on)
 verify <on|off> (Toggles SSL verification, default: on)
 exit
Note: This is blind RCE, commands executed will not return output.

SpringBreak>
```

These should be self explanitory, but to expand on base64:

**base64** is on by default and will convert commands to base64 and wrap them in `bash -c {echo,BASE64_COMMAND}|{base64,-d}|{bash,-i}`. Disabling will send raw commands through (after converting to byte array).

# References
* https://lgtm.com/blog/spring_data_rest_CVE-2017-8046_ql
