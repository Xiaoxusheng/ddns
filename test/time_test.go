package test

import (
	"log"
	"testing"
	"time"
)

func TestTime(t *testing.T) {
	t1 := time.Now()
	//启动1分钟以后
	t2 := time.Date(t1.Year(), t1.Month(), t1.Day(), t1.Hour(), t1.Minute()+1, 0, 0, t1.Location())
	log.Println("任务启动," + t2.Sub(t1).String() + "后开始执行")

	t3 := time.NewTimer(t2.Sub(t1))

	for {
		select {
		case <-t3.C:
			log.Println("脚本启动")
			t1 = time.Now()
			//一天以后执行
			t2 = time.Date(t1.Year(), t1.Month(), t1.Day(), t1.Hour()+12, t1.Minute(), 0, 0, t1.Location())
			log.Println(t2.Sub(t1))
			t3 = time.NewTimer(t2.Sub(t1))
		}
	}
}

func TestN(t *testing.T) {
	t1 := time.Now()
	t2 := time.Date(t1.Year(), t1.Month(), t1.Day(), t1.Hour(), t1.Minute()+1, 0, 0, t1.Location())
	log.Println("任务启动," + t2.Sub(t1).String() + "后开始执行")

	log.Println(t2.Before(t1))
	log.Println(t2.After(t1))

	t3 := time.NewTicker(t2.Sub(t1))

	for {
		select {
		case <-t3.C:
			log.Println("脚本启动")
			t3.Reset(time.Second * 30)
		}
	}

}
