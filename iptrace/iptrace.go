package iptrace

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2type "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

/*
List the name of ALBs
DescribeLoadBalancers: https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html
SDK for Go v2: https://github.com/aws/aws-sdk-go-v2/blob/service/elasticloadbalancingv2/v1.40.0/service/elasticloadbalancingv2/api_op_DescribeLoadBalancers.go#L21
*/
func FetchALBs() ([]string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	svc := elbv2.NewFromConfig(cfg)

	result, err := svc.DescribeLoadBalancers(context.TODO(), nil)
	if err != nil {
		return nil, err
	}

	var albNames []string
	for _, lb := range result.LoadBalancers {
		if lb.Type == elbv2type.LoadBalancerTypeEnum("application") {
			albNames = append(albNames, *lb.LoadBalancerName)
		}
	}

	return albNames, nil
}

type CloudTrailEventData struct {
	ResponseElements struct {
		NetworkInterface struct {
			Description      string `json:"description"`
			PrivateIpAddress string `json:"privateIpAddress"`
		} `json:"networkInterface"`
	} `json:"responseElements"`
}

type OutputData struct {
	EventTime        *time.Time
	PrivateIPAddress string
}

/*
Find the IP history of ALBs
LookupEvents: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
SDK for Go v2: https://github.com/aws/aws-sdk-go-v2/blob/service/cloudtrail/v1.44.2/service/cloudtrail/api_op_LookupEvents.go#L58
*/
func FetchIPhistory(albName string) ([]OutputData, error) {
	// func FetchIPhistory(albName string) string {

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	svc := cloudtrail.NewFromConfig(cfg)

	input := &cloudtrail.LookupEventsInput{
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventName,
				AttributeValue: aws.String("CreateNetworkInterface"),
			},
		},
	}

	result, err := svc.LookupEvents(context.TODO(), input)

	if err != nil {
		return nil, err
	}

	var events []OutputData
	for _, event := range result.Events {

		var cloudTrailData CloudTrailEventData
		err := json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudTrailData)
		if err != nil {
			fmt.Println("Error:", err)
			return nil, err
		}

		re := regexp.MustCompile(`ELB app\/` + albName + `\/`)
		matches := re.FindStringSubmatch(cloudTrailData.ResponseElements.NetworkInterface.Description)
		if len(matches) > 0 {
			events = append(events, OutputData{
				EventTime:        event.EventTime,
				PrivateIPAddress: cloudTrailData.ResponseElements.NetworkInterface.PrivateIpAddress,
			})
		}
	}

	return events, nil
}
