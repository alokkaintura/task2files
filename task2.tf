provider "aws" {
    region = "ap-south-1"
    profile = "alokka"
}

// Generates a secure private key and encodes it as PEM

resource "tls_private_key" "instance_key" {
  algorithm   = "RSA"
  rsa_bits = 4096
}

// Generates a local file with the given content

resource "local_file" "key_gen" {
    content = tls_private_key.instance_key.private_key_pem
    filename = "myownkey.pem"
	file_permission = 0400
}

// Provides an EC2 key pair resource

resource "aws_key_pair" "instance_key" {
  key_name   = "myownkey"
  public_key = tls_private_key.instance_key.public_key_openssh  
}

//Provides a VPC resource

resource "aws_vpc" "awsvpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"
  enable_dns_hostnames = true
  tags = {
    Name = "awsvpc"
  }
}

//Provides an VPC subnet resource

resource "aws_subnet" "public_subnet" {
  vpc_id     = aws_vpc.awsvpc.id
  cidr_block = "10.0.1.0/24"
//availability_zone = aws_instance.my_instance.availability_zone 
  availability_zone = "ap-south-1a"
  tags = {
    Name = "public_subnet"
  }
}

// Provides a resource to create a VPC Internet Gateway

resource "aws_internet_gateway" "myvpc_int_gw" {
  vpc_id = aws_vpc.awsvpc.id

  tags = {
    Name = "myvpc_int_gw"
  }
}

// Provides a resource to create a VPC routing table

resource "aws_route_table" "aws_gw_route" {
  vpc_id = aws_vpc.awsvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.myvpc_int_gw.id
  }

  tags = {
    Name = "my_gw_route"
  }
}

// Provides a resource to create an association

resource "aws_route_table_association" "taa" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.aws_gw_route.id
}

// Provides a security group resource

resource "aws_security_group" "awssg1" {
  name        = "awssg1"
  description = "Allow Inbound traffic"
  vpc_id      = aws_vpc.awsvpc.id

  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  ingress {
    description = "Allow HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }

  ingress {
    description = "Allow NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "awssg1"
  }
}

// Provides an Elastic File System (EFS) File System resource

resource "aws_efs_file_system" "efs_volume" {
  creation_token = "efs"
  performance_mode="generalPurpose"
  tags = {
    Name = "efsvolume1"
  }
}

// Provides an Elastic File System (EFS) File System Policy resource

resource "aws_efs_file_system_policy" "policy" {
  file_system_id = aws_efs_file_system.efs_volume.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-39c17487-fb13-4916-b4f9-5cae84728ba6",
    "Statement": [
        {
            "Sid": "efs-statement-26bb11a2-5826-4f9b-a378-eb321690d907",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Resource": "${aws_efs_file_system.efs_volume.arn}",
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "true"
                }
            }
        }
    ]
}
POLICY
}

// Provides an Elastic File System (EFS) mount target

resource "aws_efs_mount_target" "alpha" {
  file_system_id = aws_efs_file_system.efs_volume.id
  subnet_id      = aws_subnet.public_subnet.id
  security_groups = [ "${aws_security_group.awssg1.id}" ]
}

// Provides an EC2 instance resource

resource "aws_instance"  "my_instance" {
depends_on = [
    aws_efs_mount_target.alpha,
  ] 
    ami = "ami-00b494a3f139ba61f"
    instance_type = "t2.micro"
	associate_public_ip_address = true
	availability_zone = "ap-south-1a"
	subnet_id     = aws_subnet.public_subnet.id
    key_name =  aws_key_pair.instance_key.key_name
    vpc_security_group_ids =  [ "${aws_security_group.awssg1.id}" ] 
	
 tags = {
    Name = "aws_instance"
  }
}
resource "null_resource" "null_vol_attach"  {
depends_on = [
    aws_instance.my_instance,
  ]
  
connection {
    type = "ssh"
    user = "ec2-user"
    private_key = tls_private_key.instance_key.private_key_pem
    host = aws_instance.my_instance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sleep 30",
      "sudo yum install -y httpd git php amazon-efs-utils nfs-utils",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      "sudo chmod ugo+rw /etc/fstab",
      "sudo echo '${aws_efs_file_system.efs_volume.id}:/ /var/www/html efs tls,_netdev' >> /etc/fstab",
      "sudo mount -a -t efs,nfs4 defaults",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/alokkaintura/task2.git /var/www/html/"
    ]
  }
 	
}

// Provides a S3 bucket resource & pull image to bucket from GitHub repo

resource "aws_s3_bucket" "alokkaintura" {
  bucket = "alokkaintura"
  acl = "public-read"

  provisioner "local-exec" {
      command = "git clone https://github.com/alokkaintura/task2 new_folder"
    }
  provisioner "local-exec" {
      when = destroy
      command = "echo Y | rmdir /s new_folder"
}

depends_on = [
   null_resource.null_vol_attach,
  ]	
	

}
// Provides a S3 bucket object resource pull & image to bucket from GitHub repo

resource "aws_s3_bucket_object" "image-pull" {
    bucket = aws_s3_bucket.alokkaintura.bucket
    key = "preeti.jpg"
    source = "new_folder/dagasir.png"
    acl = "public-read"
    //content_type = "text/*"	
}





// Creates an Amazon CloudFront web distribution & using Cloudfront URL to  update in code in /var/www/html

locals {
    s3_origin_id = aws_s3_bucket.alokkaintura.bucket
    image_url = "${aws_cloudfront_distribution.s3_distribution.domain_name}/${aws_s3_bucket_object.image-pull.key}"
}

//Creates an Amazon CloudFront origin access identity

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Sync CloudFront to S3"
}





resource "aws_cloudfront_distribution" "s3_distribution" {
    origin {
        domain_name = aws_s3_bucket.alokkaintura.bucket_regional_domain_name
        origin_id = local.s3_origin_id


    s3_origin_config {
        origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
      } 
    }
	   
    # By default, show index.php file
    enabled = true
    is_ipv6_enabled = true
    default_root_object = "index.php"

    # If there is a 404, return vimal-sir.jpeg with a HTTP 200 Response
    custom_error_response {
        error_caching_min_ttl = 3000
        error_code = 404
        response_code = 200
        response_page_path = "/dagasir.jpg"
    }

    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = local.s3_origin_id

    forwarded_values {
        query_string = false
    cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "allow-all" 
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }
    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }	
	# SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
      }

    tags = {
        Name = "Web-CF-Distribution"
      }

    connection {
        type = "ssh"
        user = "ec2-user"
        private_key = tls_private_key.instance_key.private_key_pem 
        host = aws_instance.my_instance.public_ip
     }

    provisioner "remote-exec" {
        inline  = [
            "sudo su << EOF",
			"sudo chmod ugo+rw /var/www/html/",
            "echo \"<img src='http://${aws_cloudfront_distribution.s3_distribution.domain_name}/${aws_s3_bucket_object.image-pull.key}'>\" >> /var/www/html/index.php",
            "EOF"
          ]
      }
   }









output "cloudfront_ip_addr" {
  value = aws_cloudfront_distribution.s3_distribution.domain_name
}

resource "null_resource" "save_key_pair"  {
	provisioner "local-exec" {
	    command = "echo  '${tls_private_key.instance_key.private_key_pem}' > key.pem"
  	}
}

resource "null_resource" "localnull222"  {
    depends_on = [
    aws_cloudfront_distribution.s3_distribution,
   ]

    provisioner "local-exec" {
        command = "start chrome  ${aws_instance.my_instance.public_ip}"
      }
 }