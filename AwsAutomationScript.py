import boto3
import sys
import os
import time
import subprocess
import paramiko

 

def run_testcases():

 

    key = paramiko.RSAKey.from_private_key_file("./testsetup.pem")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

 

    instance_ip = "13.114.79.54"
    cmd = "bash read_test_cases.sh test_allbash read_test_cases.sh test_all"

 

    client.connect(hostname=instance_ip, username= "ec2-user", pkey=key)
    client.exec_command(cmd)
    return

 

def copy_test_folder(target_ip, pem_file):

 

    ssh_addr = "ec2-user@" + target_ip

 

    subprocess.run(['ssh', '-i', pem_file, ssh_addr, 'sudo', 'mkdir', '-m777', '-p', '/storage/1080', '/storage/tmp'])

 

    target_tests_folder = ssh_addr + ":/storage/1080"
    result_tests_folder = "/storage/1080/"

 

    subprocess.run(['scp', '-i', pem_file, '-r', test_folder, target_addr])
    print("Tests copied to the target machine.")
    return

 

def launch_instance(ec2_res):
    print ("Launching EC2 instance ....")
    instances = ec2_res.create_instances(
            ImageId='ami-0787d66c1cebe902d',
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            #KeyName='test setup',
            SecurityGroupIds=['sg-007dc268a43cac53f'],
            SubnetId='subnet-5abe2906',
            TagSpecifications=[
                {
                    'ResourceType' : 'instance',
                    'Tags' : [
                        {
                            'Key':'Name',
                            'Value':'TestingAutomationScript'
                        },
                        {
                            'Key': 'Owner',
                            'Value': 'saurabhv'
                        },
                        {
                            'Key':'Project',
                            'Value': 'Ort'
                        }
                    ]
                },
            ]
           #IamInstanceProfile={
               # 'Arn': 'arn:aws:iam::023017925022:role/OrganizationAccountAccessRole',
               # 'Name': 'OrganizationAccountAccessRole'
               # }
    )
    instance = instances[0]
    instance.wait_until_running()
    print("Instance launched")

 

    return instance

 

def get_instance_state(ec2_res, inst_id):
    for each in ec2_res.instances.filter(Filters=[{'Name':'instance-id',"Values":[inst_id]}]):
        pr_st=each.state['Name']
        return pr_st

 

def start_instance(ec2_res, inst_id):
    pr_st=get_instance_state(ec2_res, inst_id)
    if pr_st == "running":
        print("Instance is already running")
    else:
        for each in ec2_res.instances.filter(Filters=[{'Name':'instance-id',"Values":[inst_id]}]):
            each.start()
            print("Please wait it is going to start, once if it is started then we will let you know.")
            each.wait_until_running()
            print("Now it is running.")
    return

 

def stop_instance(ec2_res, inst_id):
    pr_st=get_instance_state(ec2_res, inst_id)
    if pr_st == "stopped":
        print("Instance is already stopped.")
    else:
        for each in ec2_res.instances.filter(Filters=[{'Name':'instance-id', "Values":[inst_id]}]):
            each.stop()
            print("Please wait it is going to stop, once it is stopped then we will let you know.")
            each.wait_until_stopped()
            print("Instance stopped.")
    return

 

def main():

 

    sts_client = boto3.client('sts')

 

    assumed_role_object = sts_client.assume_role(
            RoleArn="arn:aws:iam::023017925022:role/OrganizationAccountAccessRole",
            RoleSessionName="OrganizationAccountAccessRole"
    )

 

    credentials = assumed_role_object['Credentials']
    ec2_res = boto3.resource('ec2', aws_access_key_id=credentials['AccessKeyId'], 
				aws_secret_access_key=credentials['SecretAccessKey'],
                            	aws_session_token=credentials['SessionToken'])

 


    target_instance = launch_instance(ec2_res)
    target_instance.reload
    target_ip = target_instance.public_ip_address
    target_id = target_instance.id

 

    pem_file = "testsetup.pem"

 

    copy_test_folder(target_ip, pem_file)

 

    #Running testcases. If this command doesn't work on result machine, then try 'run_testcases' function, defined within this script.
    subprocess.run(['ssh', '-i', pem_file, 'ec2-user@'+target_ip, 'bash', 'read_test_cases.sh', 'test_allbash', 'read_test_cases.sh', 'test_all'])

 

    #Need to copy test results from target machine(/storage/tmp) to result machine.

 

    #Terminating target instance.
    target_instance.terminate()

 


if __name__ == '__main__':
    #os.system('cls')
    main()
