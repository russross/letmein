LetMeIn
=======

A password generating tool that uses scrypt and a master password to
generate strong passwords. Instead of storing the passwords, it
re-generates them each time you need them.

To install, you must have Go installed and configured, then run:

    go get github.com/russross/letmein

Assuming `$GOPATH/bin` is in your PATH, you can then initialize it
using:

    letmein init -name your_account_name

Your account name can be anything, but I suggest using a gmail
address or other Google account name. This version is just for
experimenting; later you will be required to log in using a Google
credential and the name will be gleaned from your account
automatically.

You can supply your master password from the command line, or you
can set put it in the environment:

    export LETMEIN_PASSWORD=letmein

To see the list of commands:

    letmein help

To create a sample profile:

    letmein create -url github.com -username yourname -length 20 -punctuation=false

Then you can list your profiles with generated passwords:

    letmein list

Or just list some of them:

    letmein list -url github

To sync them with the server:

    letmein sync

To see the request data and response data:

    letmein sync -v

letmein stores its data in `$HOME/.letmeinrc`, so you can delete
that file to start over (although this will not reset the server
state: to do that you must contact me directly).
