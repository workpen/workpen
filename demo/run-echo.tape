# Record with vhs 0.11.x (v0.12.0 writes no GIF: charmbracelet/vhs#787):
#   sed "s|__WORKPEN_BINDIR__|$(pwd)/target/debug|" demo/run-echo.tape > /tmp/workpen-demo.tape
#   vhs /tmp/workpen-demo.tape
Output demo/run-echo.gif
Set Shell "bash"
Set FontSize 16
Set Width 980
Set Height 260
Set Theme "Catppuccin Mocha"
Set Framerate 25
Set TypingSpeed 40ms
Set CursorBlink false
Set Padding 16

Hide
Type "export PATH=__WORKPEN_BINDIR__:$PATH"
Enter
Type "mkdir -p /tmp/wp-demo && printf 'SECRET=1\n' > /tmp/wp-demo/.env && cd /tmp/wp-demo && clear"
Enter
Sleep 250ms
Type "workpen why --root . .env"
Enter
Sleep 900ms
Show

Sleep 1200ms
Type "workpen run --root . -- /bin/echo ok"
Enter
Sleep 2000ms
