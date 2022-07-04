package main

import (
	"fmt"
	"log"
	"github.com/golang-jwt/jwt/v4"
)

const key = "my secure jwt key"

type UserClaim struct {
	jwt.RegisteredClaims
	ID    int 
	Email string
	Name  string
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
		ID: id,
		Email: email,
		Name: name,
	})

	signedString, err := token.SignedString([]byte(key))

	if err != nil {
		return "", fmt.Errorf("error creating signed string: %v", err)
	}

	return signedString, nil
}

func ParseJWTToken(jwtToken string, userClaim *UserClaim) error {
	token, err := jwt.ParseWithClaims(jwtToken, userClaim, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}
