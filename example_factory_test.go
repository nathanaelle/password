package	password

import	(
	"os"
	"flag"
	"strings"
	"fmt"
)


func ExampleFactory() {
	fs	:= flag.NewFlagSet("", flag.ExitOnError)
	fact	:= &Factory {
		CustomFlagHelper: func(d []string) string {
			return "type of password accepted : "+strings.Join(d, ", ")
		},
	}

	fact.Register(SHA256, SHA512, BCRYPT)
	fs.SetOutput(os.Stdout)
	fs.Var(fact, "password", fact.FlagHelper())

	fs.PrintDefaults()
	fs.Parse([]string{"-password=$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."})

	crypter	:= fact.CrypterFound()
	fmt.Printf("this password is %s\n", crypter.Definition().String())

	// Output:
	// -password value
	//     	type of password accepted : {SHA256-CRYPT}, {SHA512-CRYPT}, {BLF-CRYPT}
	// this password is {BLF-CRYPT}
	//
}
