package jwt_utils

import(
  "log"
  "fmt"
  "time"

	jwt "github.com/dgrijalva/jwt-go"
)


type myClaims struct {
	jwt.StandardClaims
	Name     string `json:"Name"`
	Email    string `json:"Email"`
	ID       uint   `json:"id"`
  StoreID  uint   `json:"store_id"`
  StoreCode string `json:"store_code"`
	RoleID	 uint		`json:"role_id"`
  Role     string `json:"role"`
	Scope    string `json:"scope"`
}

type JwtUtils struct{
  TokenDuration time.Duration
  TokenExpAt    time.Time
  SecretKey     string
  Claims        *myClaims
}

func NewJWTUtils(secret string, duration time.Duration) *JwtUtils{
  return &JwtUtils{SecretKey : secret, TokenDuration: duration}
}

func(u *JwtUtils) GenerateClaims(m map[string]interface{}) ( error){
  u.TokenExpAt = time.Now().Add(u.TokenDuration)
  u.Claims = &myClaims{ StandardClaims: jwt.StandardClaims{
              			Issuer:    m["email"].(string),
              			ExpiresAt: u.TokenExpAt.Unix(),
              		},
              		Name:     m["name"].(string),
              		Email:    m["email"].(string),
              		ID:       uint(m["id"].(float64)),
                  StoreID:  uint(m["store_id"].(float64)),
                  StoreCode:  m["store_code"].(string),
              		RoleID:   uint(m["role"].(float64)),
              		Role: 	  m["role_name"].(string),
              		Scope:    m["scope"].(string),
              	}
	return nil
}

func(u *JwtUtils) GenerateTokenPair() (map[string]interface{}, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS384, u.Claims)

  expAt := u.Claims.StandardClaims.ExpiresAt
  expIn := expAt - time.Now().Unix()
	// Generate encoded token and send it as response.
	// The signing string should be secret (a generated UUID works too)
	t, err := token.SignedString([]byte(u.SecretKey))
	if err != nil {
    log.Println(err)
		return nil, err
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["sub"] = u.Claims.ID
	rtClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	rt, err := refreshToken.SignedString([]byte(u.SecretKey))
	if err != nil {
    log.Println(err)
		return nil, err
	}

	return map[string]interface{}{
		"access_token":  t,
		"expires_at" : expAt,
    "expires_in": expIn,
		"refresh_token": rt,
    "refresh_token_expires_at" : rtClaims["exp"],
	}, nil
}

func (u *JwtUtils) ParseBearerToken(bearerToken string) (*jwt.Token, error) {
	return jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(u.SecretKey), nil
	})
}
