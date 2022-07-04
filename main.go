package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"log"
)

const key = "my secure jwt key"

// custom token payload
type UserClaim struct {
	jwt.RegisteredClaims
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func main() {
	jwtToken, err := CreateJWTToken(1, "email@email.com", "First Last")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT Token: %s\n", jwtToken)

	var userClaim UserClaim

	err = ParseJWTToken(jwtToken, &userClaim)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed User Claim: %d %s %s\n", userClaim.ID, userClaim.Email, userClaim.Name)
}

func CreateJWTToken(id int, email string, name string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaim{
		RegisteredClaims: jwt.RegisteredClaims{},
		ID:               id,
		Email:            email,
		Name:             name,
	})

	signedString, err := token.SignedString([]byte(key))

	if err != nil {
		return "", fmt.Errorf("error creating signed string: %v", err)
	}

	return signedString, nil
}

func ParseJWTToken(jwtToken string, userClaim *UserClaim) error {
	token, err := jwt.ParseWithClaims(jwtToken, userClaim, func(token *jwt.Token) (interface{}, error) {
		// returning the secret key
		return []byte(key), nil
	})
	if err != nil {
		return err
	}

	// check token validity, for example token might have been expired
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}
