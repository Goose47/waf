package main

import (
	"encoding/json"
	"fmt"
	"github.com/IBM/sarama"
	"log"
	"time"
)

func main() {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForLocal
	config.Producer.Return.Errors = true
	config.Producer.Return.Successes = true

	brokers := []string{"kafka:29092"}
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Fatalf("Failed to create producer: %v", err)
	}
	defer producer.Close()

	for {
		type message struct {
			Ip string `json:"ip"`
		}

		marshalled, _ := json.Marshal(message{Ip: "12345"})

		msg := &sarama.ProducerMessage{
			Topic: "detection",
			Value: sarama.StringEncoder(marshalled),
		}

		partition, offset, err := producer.SendMessage(msg)
		if err != nil {
			log.Printf("Failed to send message: %v", err)
		} else {
			fmt.Printf("Message sent to partition %d at offset %d\n", partition, offset)
		}

		time.Sleep(time.Second * 5)
	}
}
