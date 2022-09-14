package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strings"
	"time"
)

type MyCustomClaims struct {
	Email    string `json:"email"`
	Birthday int64  `json:"birthday"`
	jwt.RegisteredClaims
}

var mySecret = "my-secret"

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/generate-token", GenerateToken)
	router.HandleFunc("/validate-token", ValidateToken)
	http.ListenAndServe("localhost:8080", router)
}

func GenerateToken(w http.ResponseWriter, r *http.Request) {
	claims := MyCustomClaims{
		"hello@friendsofgo.tech",
		time.Date(2019, 01, 01, 0, 0, 0, 0, time.UTC).Unix(),
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "test",
			Subject:   "somebody",
			ID:        "1",
			Audience:  []string{"somebody_else"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(mySecret))
	if err != nil {
		log.Println(err)
	}
	w.Write([]byte(signedToken))
	w.WriteHeader(http.StatusOK)
}

func ValidateToken(w http.ResponseWriter, r *http.Request) {
	receivedToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", -1)

	token, err := jwt.ParseWithClaims(receivedToken, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(mySecret), nil
	})

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		w.Write([]byte(fmt.Sprintf("%s,%d", claims.Email, claims.Birthday)))
		w.WriteHeader(http.StatusOK)
	} else {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusBadRequest)
	}
}
