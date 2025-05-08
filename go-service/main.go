package main

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	store := cookie.NewStore([]byte("secret"))
	r := gin.Default()
	r.Use(sessions.Sessions("mysession", store))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	r.GET("/test", func(context *gin.Context) {
		se := sessions.Default(context)
		//var op sessions.Options
		//op.MaxAge=100
		//se.Options(op)
		if se.Get("key") == nil {
			se.Set("key", time.Now().GoString())
		}
	})
	err := r.Run()
	if err != nil {
		fmt.Println(err)
		return
	} // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
