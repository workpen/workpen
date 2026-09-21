# Record with vhs 0.11.x (v0.12.0 writes no GIF: charmbracelet/vhs#787):
#   sed "s|__WORKPEN_BINDIR__|$(pwd)/target/debug|" demo/dest-deny.tape > /tmp/workpen-demo.tape
#   vhs /tmp/workpen-demo.tape
Output demo/dest-deny.gif
Set Shell "bash"
Set FontSize 16
Set Width 1040
Set Height 400
Set Theme "Catppuccin Mocha"
Set Framerate 25
Set TypingSpeed 35ms
Set CursorBlink false
Set Padding 16

Hide
Type "export PATH=__WORKPEN_BINDIR__:$PATH"
Enter
Type "rm -rf /tmp/wp && mkdir /tmp/wp && cd /tmp/wp && printf 'SECRET=1\n' > .env && printf 'hello notes\n' > notes.md && ln .env notes.txt && clear"
Enter
Sleep 250ms
Type "workpen why --root . .env"
Enter
Sleep 800ms
Show

Sleep 1000ms
Type "workpen why --root . notes.txt"
Enter
Sleep 1000ms
Type "workpen why --root . notes.md"
Enter
Sleep 800ms
Type "workpen run --root . -- /bin/cat notes.md"
Enter
Sleep 2000ms
