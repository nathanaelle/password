package	password

import	(
	"encoding/json"
	"fmt"
	"log"
)


func ExampleJSONFactory() {
	var t  struct {
		Password   *Factory	`json:"pwd"`
	}

	data	:= []byte(`{"pwd":"$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."}`)

	if err := json.Unmarshal(data, &t); err != nil {
		log.Fatal(err)
	}

	if t.Password == nil {
		log.Fatal("no password parsed")
	}

	crypter := t.Password.CrypterFound()
	if crypter == nil {
		log.Fatal("no password found")
	}

	fmt.Printf("the password in json %s is a %v\n", data, crypter.Definition())

	// Output:
	// the password in json {"pwd":"$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."} is a {BLF-CRYPT}
	//
}
