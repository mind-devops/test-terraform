# terraform {
#     required_providers {
#         aws = {
#             source = "hashicorp/aws"
#             version = "~> 3.0"
#         }
#     }
# }

provider "aws" {
    region = "us-east-1"
}

resource "aws_iam_role" "IAMRole" {
    path = "/"
    name = "WAFSECURITYHTTP-FirehoseA-FirehoseWAFLogsDeliveryS-WPRVPM5DCTY3"
    assume_role_policy = "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"firehose.amazonaws.com\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"697611382054\"}}}]}"
    max_session_duration = 3600
    # tags {}
}

resource "aws_iam_role" "IAMRole2" {
    path = "/"
    name = "WAFSECURITYHTTP-LambdaRoleCustomResource-TZJWEMP1Z923"
    assume_role_policy = "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    # tags {}
}

resource "aws_iam_role" "IAMRole3" {
    path = "/"
    name = "WAFSECURITYHTTP-LambdaRoleLogParser-20RG7OUT21ML"
    assume_role_policy = "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    # tags {}
}

resource "aws_iam_role" "IAMRole4" {
    path = "/"
    name = "WAFSECURITYHTTP-LambdaRoleHelper-1CVVXE6RJ559O"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    # tags {}
}

resource "aws_iam_role" "IAMRole5" {
    path = "/"
    name = "WAFSECURITYHTTP-WebACLStack-LambdaRoleCustomTimer-1PXVGPLUY3M4S"
    assume_role_policy = "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    # tags {}
}

resource "aws_iam_role_policy" "IAMPolicy" {
    policy = "{\"Statement\":[{\"Action\":[\"logs:PutLogEvents\"],\"Resource\":[\"arn:aws:logs:us-east-1:697611382054:log-group:/aws/kinesisfirehose/aws-waf-logs-WAFSECURITYHTTP_C6MeZw:*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole.name}"
}

resource "aws_iam_role_policy" "IAMPolicy2" {
    policy = "{\"Statement\":[{\"Action\":[\"kinesis:DescribeStream\",\"kinesis:GetShardIterator\",\"kinesis:GetRecords\"],\"Resource\":[\"arn:aws:kinesis:us-east-1:697611382054:stream/aws-waf-logs-WAFSECURITYHTTP_C6MeZw\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole.name}"
}

resource "aws_iam_role_policy" "IAMPolicy3" {
    policy = "{\"Statement\":[{\"Action\":[\"s3:AbortMultipartUpload\",\"s3:GetBucketLocation\",\"s3:GetObject\",\"s3:ListBucket\",\"s3:ListBucketMultipartUploads\",\"s3:PutObject\"],\"Resource\":[\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae\",\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae/*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole.name}"
}

resource "aws_iam_role_policy" "IAMPolicy4" {
    policy = "{\"Statement\":[{\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":[\"arn:aws:logs:us-east-1:697611382054:log-group:/aws/lambda/*CustomResource*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy5" {
    policy = "{\"Statement\":[{\"Action\":[\"s3:GetBucketLocation\",\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy6" {
    policy = "{\"Statement\":[{\"Action\":[\"wafv2:GetIPSet\",\"wafv2:DeleteIPSet\"],\"Resource\":[\"arn:aws:wafv2:us-east-1:697611382054:regional/ipset/WAFSECURITYHTTP*\",\"arn:aws:wafv2:us-east-1:697611382054:global/ipset/WAFSECURITYHTTP*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy7" {
    policy = "{\"Statement\":[{\"Action\":\"cloudformation:DescribeStacks\",\"Resource\":[\"arn:aws:cloudformation:us-east-1:697611382054:stack/WAFSECURITYHTTP/*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy8" {
    policy = "{\"Statement\":[{\"Action\":[\"s3:CreateBucket\",\"s3:GetBucketNotification\",\"s3:PutBucketNotification\",\"s3:PutEncryptionConfiguration\",\"s3:PutBucketPublicAccessBlock\"],\"Resource\":[\"arn:aws:s3:::\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy9" {
    policy = "{\"Statement\":[{\"Action\":[\"s3:CreateBucket\",\"s3:GetBucketNotification\",\"s3:PutBucketNotification\"],\"Resource\":[\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy10" {
    policy = "{\"Statement\":[{\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae/WAFSECURITYHTTP-waf_log_conf.json\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy11" {
    policy = "{\"Statement\":[{\"Action\":[\"wafv2:GetWebACL\",\"wafv2:UpdateWebACL\",\"wafv2:DeleteLoggingConfiguration\"],\"Resource\":[\"arn:aws:wafv2:us-east-1:697611382054:global/webacl/WAFSECURITYHTTP/c47f8749-afbb-45aa-bad8-f04a5f0b3377\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy12" {
    policy = "{\"Statement\":[{\"Action\":[\"wafv2:PutLoggingConfiguration\"],\"Resource\":[\"arn:aws:wafv2:us-east-1:697611382054:global/webacl/WAFSECURITYHTTP/c47f8749-afbb-45aa-bad8-f04a5f0b3377\"],\"Effect\":\"Allow\"},{\"Condition\":{\"StringLike\":{\"iam:AWSServiceName\":\"wafv2.amazonaws.com\"}},\"Action\":\"iam:CreateServiceLinkedRole\",\"Resource\":[\"arn:aws:iam::*:role/aws-service-role/wafv2.amazonaws.com/AWSServiceRoleForWAFV2Logging\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole2.name}"
}

resource "aws_iam_role_policy" "IAMPolicy13" {
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":[\"arn:aws:logs:us-east-1:697611382054:log-group:/aws/lambda/*Helper*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole4.name}"
}

resource "aws_iam_role_policy" "IAMPolicy14" {
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"s3:GetBucketLocation\",\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole4.name}"
}

resource "aws_iam_role_policy" "IAMPolicy15" {
    policy = "{\"Statement\":[{\"Action\":[\"wafv2:ListWebACLs\"],\"Resource\":[\"arn:aws:wafv2:us-east-1:697611382054:regional/webacl/*\",\"arn:aws:wafv2:us-east-1:697611382054:global/webacl/*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole4.name}"
}

resource "aws_iam_role_policy" "IAMPolicy16" {
    policy = "{\"Statement\":[{\"Action\":\"cloudwatch:GetMetricStatistics\",\"Resource\":[\"*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole3.name}"
}

resource "aws_iam_role_policy" "IAMPolicy17" {
    policy = "{\"Statement\":[{\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":[\"arn:aws:logs:us-east-1:697611382054:log-group:/aws/lambda/*LogParser*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole3.name}"
}

resource "aws_iam_role_policy" "IAMPolicy18" {
    policy = "{\"Statement\":[{\"Action\":\"s3:GetObject\",\"Resource\":[\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae/*\"],\"Effect\":\"Allow\"},{\"Action\":\"s3:PutObject\",\"Resource\":[\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae/WAFSECURITYHTTP-waf_log_out.json\",\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae/WAFSECURITYHTTP-waf_log_conf.json\"],\"Effect\":\"Allow\"},{\"Action\":[\"wafv2:GetIPSet\",\"wafv2:UpdateIPSet\"],\"Resource\":[\"arn:aws:wafv2:us-east-1:697611382054:global/ipset/WAFSECURITYHTTPHTTPFloodSetIPV4/0cb406b2-6177-49f2-adc6-0e5fb6918cf5\",\"arn:aws:wafv2:us-east-1:697611382054:global/ipset/WAFSECURITYHTTPHTTPFloodSetIPV6/bf4d783a-4c82-49ce-86ab-a84748ee45dc\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole3.name}"
}

resource "aws_iam_role_policy" "IAMPolicy19" {
    policy = "{\"Statement\":[{\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":[\"arn:aws:logs:us-east-1:697611382054:log-group:/aws/lambda/*CustomTimer*\"],\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole5.name}"
}

resource "aws_lambda_function" "LambdaFunction" {
    description = "This lambda function verifies the main project's dependencies, requirements and implement auxiliary functions."
    environment {
        variables = {
            SCOPE = "CLOUDFRONT"
            USER_AGENT_EXTRA = "AwsSolution/SO0006/v3.2.0"
            LOG_LEVEL = "INFO"
        }
    }
    function_name = "WAFSECURITYHTTP-Helper-e14PZipkCJ4n"
    handler = "helper.lambda_handler"
    architectures = [
        "x86_64"
    ]
    
    filename = "./helper.zip"
    memory_size = 128
    role = "${aws_iam_role.IAMRole4.arn}"
    runtime = "python3.8"
    timeout = 300
    tracing_config {
        mode = "PassThrough"
    }
}

resource "aws_lambda_function" "LambdaFunction2" {
    description = "This lambda function counts X seconds and can be used to slow down component creation in CloudFormation"
    environment {
        variables = {
            SECONDS = "2"
            LOG_LEVEL = "INFO"
        }
    }
    function_name = "WAFSECURITYHTTP-WebACLStack-1CTDOD6XCX-CustomTimer-k3F8qDxm9jlE"
    handler = "timer.lambda_handler"
    architectures = [
        "x86_64"
    ]
    
    filename = "./timer.zip"
    memory_size = 128
    role = "${aws_iam_role.IAMRole5.arn}"
    runtime = "python3.8"
    timeout = 300
    tracing_config {
        mode = "PassThrough"
    }
}

resource "aws_lambda_function" "LambdaFunction3" {
    description = "This lambda function configures the Web ACL rules based on the features enabled in the CloudFormation template."
    environment {
        variables = {
            METRICS_URL = "https://metrics.awssolutionsbuilder.com/generic"
            SOLUTION_ID = "SO0006"
            SCOPE = "CLOUDFRONT"
            USER_AGENT_EXTRA = "AwsSolution/SO0006/v3.2.0"
            LOG_LEVEL = "INFO"
        }
    }
    function_name = "WAFSECURITYHTTP-CustomResource-HXaAHGyqkv9x"
    handler = "custom-resource.lambda_handler"
    architectures = [
        "x86_64"
    ]
    
    filename = "./custom_resource.zip"
    memory_size = 128
    role = "${aws_iam_role.IAMRole2.arn}"
    runtime = "python3.8"
    timeout = 300
    tracing_config {
        mode = "PassThrough"
    }
}

resource "aws_lambda_function" "LambdaFunction4" {
    description = "This function parses access logs to identify suspicious behavior, such as an abnormal amount of errors. It then blocks those IP addresses for a customer-defined period of time."
    environment {
        variables = {
            ERROR_THRESHOLD = "50"
            IP_SET_ID_HTTP_FLOODV4 = "arn:aws:wafv2:us-east-1:697611382054:global/ipset/WAFSECURITYHTTPHTTPFloodSetIPV4/0cb406b2-6177-49f2-adc6-0e5fb6918cf5"
            WAF_ACCESS_LOG_BUCKET = "wafsecurityhttp-waflogbucket-kxoyax5tzoae"
            METRIC_NAME_PREFIX = "WAFSECURITYHTTP"
            SOLUTION_ID = "SO0006"
            IP_SET_ID_HTTP_FLOODV6 = "arn:aws:wafv2:us-east-1:697611382054:global/ipset/WAFSECURITYHTTPHTTPFloodSetIPV6/bf4d783a-4c82-49ce-86ab-a84748ee45dc"
            REQUEST_THRESHOLD = "10"
            SEND_ANONYMOUS_USAGE_DATA = "Yes"
            SCOPE = "CLOUDFRONT"
            LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION = "10000"
            WAF_BLOCK_PERIOD = "24"
            MAX_AGE_TO_UPDATE = "30"
            STACK_NAME = "WAFSECURITYHTTP"
            REGION = "us-east-1"
            METRICS_URL = "https://metrics.awssolutionsbuilder.com/generic"
            IP_SET_NAME_HTTP_FLOODV6 = "WAFSECURITYHTTPHTTPFloodSetIPV6"
            IP_SET_NAME_HTTP_FLOODV4 = "WAFSECURITYHTTPHTTPFloodSetIPV4"
            LOG_TYPE = "cloudfront"
            USER_AGENT_EXTRA = "AwsSolution/SO0006/v3.2.0"
            UUID = "e1894eaf-7e6c-4e35-a91d-78886d90b320"
            LOG_LEVEL = "INFO"
        }
    }
    function_name = "WAFSECURITYHTTP-LogParser-3Ug708OwmJv8"
    handler = "log-parser.lambda_handler"
    architectures = [
        "x86_64"
    ]
    
     filename = "./log_parser.zip"

    role = "${aws_iam_role.IAMRole3.arn}"
    runtime = "python3.8"
    timeout = 300
    tracing_config {
        mode = "PassThrough"
    }
}



resource "aws_s3_bucket" "S3Bucket" {
    bucket = "wafsecurityhttp-waflogbucket-kxoyax5tzoae"
}

resource "aws_s3_bucket" "S3Bucket2" {
    bucket = "wafsecurityhttp-accessloggingbucket-183egj0zvm0zz"
}


resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.S3Bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.LambdaFunction4.arn
    events              = ["s3:ObjectCreated:*"]
    # filter_prefix       = "AWSLogs/"
    filter_suffix       = "gx"
  }
}

resource "aws_lambda_permission" "test" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunction4.arn
  principal = "s3.amazonaws.com"
  source_arn = "arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae"
}

resource "aws_s3_bucket_policy" "S3BucketPolicy" {
    bucket = aws_s3_bucket.S3Bucket.id
    policy = "{\"Version\":\"2012-10-17\",\"Id\":\"AWSLogDeliveryWrite20150319\",\"Statement\":[{\"Sid\":\"AWSLogDeliveryWrite\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"delivery.logs.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae/AWSLogs/697611382054/*\",\"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"697611382054\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"},\"ArnLike\":{\"aws:SourceArn\":\"arn:aws:logs:us-east-1:697611382054:*\"}}},{\"Sid\":\"AWSLogDeliveryAclCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"delivery.logs.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::wafsecurityhttp-waflogbucket-kxoyax5tzoae\",\"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"697611382054\"},\"ArnLike\":{\"aws:SourceArn\":\"arn:aws:logs:us-east-1:697611382054:*\"}}}]}"
}

resource "aws_wafv2_ip_set" "IPTEST" {
  name               = "WAFSECURITYHTTPBlacklistSetIPV4"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
#   addresses          = ["1.1.1.1/32", "2.2.2.2/32"]
}
resource "aws_wafv2_ip_set" "IPTEST2" {
  name               = "WAFSECURITYHTTPBlacklistSetIPV6"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
#   addresses          = ["1.1.1.1/32", "2.2.2.2/32"]
}
resource "aws_wafv2_ip_set" "IPTEST3" {
  name               = "WAFSECURITYHTTPHTTPFloodSetIPV4"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
#   addresses          = ["1.1.1.1/32", "2.2.2.2/32"]
}
resource "aws_wafv2_ip_set" "IPTEST4" {
  name               = "WAFSECURITYHTTPHTTPFloodSetIPV6"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
#   addresses          = ["1.1.1.1/32", "2.2.2.2/32"]
}
resource "aws_wafv2_ip_set" "IPTEST5" {
  name               = "WAFSECURITYHTTPWhitelistSetIPV4"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
#   addresses          = ["1.1.1.1/32", "2.2.2.2/32"]
}
resource "aws_wafv2_ip_set" "IPTEST6" {
  name               = "WAFSECURITYHTTPWhitelistSetIPV6"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
#   addresses          = ["1.1.1.1/32", "2.2.2.2/32"]
}

resource "aws_wafv2_web_acl" "WAFSECURITYHTTP" {
    name        = "WAFSECURITYHTTP"
    description = "Custom WAFWebACL"
    scope       = "CLOUDFRONT"
  
    default_action {
      allow {}
    }

    rule {
        name     = "WAFSECURITYHTTPWhitelistRule"
        priority = 1

        #override_action {
        #    count {}
        #  }

        action {
        allow {}
        }

        statement {

        or_statement {
            statement {
                ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.IPTEST5.arn
                  }
                  }

            statement{
                  ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.IPTEST6.arn
                  }
                }
            }
        }
        
        visibility_config {
            cloudwatch_metrics_enabled = true
            metric_name                = "WAFSECURITYHTTPWhitelistRule"
            sampled_requests_enabled   = true
        }

    }

    
    rule {
        name     = "WAFSECURITYHTTPBlacklistRule"
        priority = 2

        #override_action {
        #   count {}
        # }

        action {
        block {}
        }

        statement {

        or_statement {
            statement {
                ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.IPTEST.arn
                  }
                }
            statement{

                  ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.IPTEST2.arn
                  }
            }

            
        }
        }
        visibility_config {
            cloudwatch_metrics_enabled = true
            metric_name                = "WAFSECURITYHTTPBlacklistRule"
            sampled_requests_enabled   = true
        }

    }

    
    rule {
        name     = "WAFSECURITYHTTPHttpFloodRegularRule"
        priority = 0

        #override_action {
        #   count {}
        #}

        action {
        block {}    
        }

        statement {

        or_statement {
            statement {
                ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.IPTEST3.arn
                  }
                }
            statement{

                  ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.IPTEST4.arn
                  }
                }

            }    
        }
        
        visibility_config {
            cloudwatch_metrics_enabled = true
            metric_name                = "WAFSECURITYHTTPHttpFloodRegularRule"
            sampled_requests_enabled   = true    
        }

    }
    
    visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "WAFSECURITYHTTPWAFWebACL"
        sampled_requests_enabled   = true
    }

}





resource "aws_cloudwatch_dashboard" "CloudWatchDashboard" {
dashboard_name = "WAFSECURITYHTTP-us-east-1"
dashboard_body = <<EOF
{
"widgets": [{
"type": "metric",
"x": 0,
"y": 0,
"width": 15,
"height": 10,
"properties": {
"view": "timeSeries",
"stacked": false,
"stat": "Sum",
"period": 300,
"metrics": [
["WAF", "BlockedRequests", "WebACL", "WAFSECURITYHTTPMaliciousRequesters", "Rule", "ALL" ],
["WAF", "AllowedRequests", "WebACL", "WAFSECURITYHTTPMaliciousRequesters", "Rule", "ALL" ]
],
"region": "us-east-1"
}
}]
}
EOF
}


resource "aws_kinesis_firehose_delivery_stream" "extended_s3_stream" {
  name        = "aws-waf-logs-WAFSECURITYHTTP_ONg9yc"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.IAMRole.arn
    bucket_arn = aws_s3_bucket.S3Bucket.arn
    buffer_interval    = 300
    compression_format = "GZIP"


  

    processing_configuration {
      enabled = "false"

    
    }
    
  }
}


















