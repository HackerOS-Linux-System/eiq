package main

import "core:os"
import "core:fmt"
import "core:flags"
import "core:sys/posix"

print_help :: proc() {
    fmt.println("Usage: [program] <command> [options]")
    fmt.println("Commands:")
    fmt.println("  up        Bring up the service (requires root)")
    fmt.println("  down      Bring down the service (requires root)")
    fmt.println("  daemon    Run as daemon (requires root)")
    fmt.println("  encrypt   Encrypt a file")
    fmt.println("    file                  Input file")
    fmt.println("    -o, --out <file>      Output file (default: input.eiq)")
    fmt.println("    -p, --password <pass> Password (required)")
    fmt.println("  decrypt   Decrypt a file")
    fmt.println("    file                  Input file")
    fmt.println("    -o, --out <file>      Output file (required)")
    fmt.println("    -p, --password <pass> Password (required)")
}

cmd_up :: proc() {
    // Stub: Implement up functionality here
    fmt.println("Executing up command")
}

cmd_down :: proc() {
    // Stub: Implement down functionality here
    fmt.println("Executing down command")
}

cmd_daemon :: proc() {
    // Stub: Implement daemon functionality here
    fmt.println("Executing daemon command")
}

encrypt_file :: proc(input: string, output: string, password: string) {
    // Stub: Implement file encryption here (potentially using statically linked C/C++ libs for crypto)
    fmt.printf("Encrypting %s to %s with password %s\n", input, output, password)
}

decrypt_file :: proc(input: string, output: string, password: string) {
    // Stub: Implement file decryption here (potentially using statically linked C/C++ libs for crypto)
    fmt.printf("Decrypting %s to %s with password %s\n", input, output, password)
}

main :: proc() {
    if len(os.args) < 2 {
        print_help()
        os.exit(1)
    }

    cmd := os.args[1]
    need_root := cmd == "up" || cmd == "down" || cmd == "daemon"
    if need_root && posix.getuid() != 0 {
        fmt.println("[-] Needs root for up/down/daemon")
        os.exit(1)
    }

    switch cmd {
    case "up":
        cmd_up()
    case "down":
        cmd_down()
    case "daemon":
        cmd_daemon()
    case "encrypt":
        Encrypt_Args :: struct {
            file:     string `args:"pos=0,usage=Input file"`,
            out:      string `args:"name=out,o,usage=Output file"`,
            password: string `args:"name=password,p,required,usage=Password"`,
        }
        args_struct: Encrypt_Args
        err := flags.parse(&args_struct, os.args[2:], .Unix)
        if err != nil {
            fmt.println(err)
            print_help()
            os.exit(1)
        }
        out := args_struct.out
        if out == "" {
            out = args_struct.file + ".eiq"
        }
        encrypt_file(args_struct.file, out, args_struct.password)
    case "decrypt":
        Decrypt_Args :: struct {
            file:     string `args:"pos=0,usage=Input file"`,
            out:      string `args:"name=out,o,required,usage=Output file"`,
            password: string `args:"name=password,p,required,usage=Password"`,
        }
        args_struct: Decrypt_Args
        err := flags.parse(&args_struct, os.args[2:], .Unix)
        if err != nil {
            fmt.println(err)
            print_help()
            os.exit(1)
        }
        decrypt_file(args_struct.file, args_struct.out, args_struct.password)
    case:
        print_help()
        os.exit(1)
    }
}
