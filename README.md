## Associate Cloud Service Provider Account

(venv) python3 cor-multicloud.py associate-account --input_yaml aws-config.yaml

Associating the cloud service provider account
╒══════════════╤════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╕
│   Account Id │ Region List                                                                                                                                                                                                                                                    │
╞══════════════╪════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╡
│ 010098612700 │ ['eu-north-1', 'ap-south-1', 'eu-west-3', 'eu-west-2', 'eu-west-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-northeast-1', 'sa-east-1', 'ca-central-1', 'ap-southeast-1', 'ap-southeast-2', 'eu-central-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'] │
╘══════════════╧════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╛
(venv) msuchand@MSUCHAND-M-F109 devnet2096 %

## Configure Global Settings

(venv) python3 cor-multicloud.py multicloud-globalsettings

Configuring Multi Cloud Global Settings
Configured/updated Multi Cloud Global Settings


## Discover Host VPCs

(venv) python3 cor-multicloud.py discover-hostvpc

Discovering Host VPCs in associated Cloud Service Provider account
╒════════════════╤════════════════╤═══════════════════════╤═════════════════╕
│ Account Name   │ Region         │ Host VPC ID           │ Host VPC Name   │
╞════════════════╪════════════════╪═══════════════════════╪═════════════════╡
│ Cloud-TME      │ sa-east-1      │ vpc-acf8b3cb          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ap-northeast-1 │ vpc-65c2e502          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ca-central-1   │ vpc-3dc6a555          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ap-southeast-1 │ vpc-f27f5595          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ eu-west-1      │ vpc-11cdfa77          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ eu-central-1   │ vpc-212b2c4a          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ eu-north-1     │ vpc-55f2003c          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ eu-west-2      │ vpc-f0900898          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ap-northeast-2 │ vpc-a94ba4c2          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ap-northeast-3 │ vpc-76e8891f          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ eu-west-3      │ vpc-6d755404          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ us-west-2      │ vpc-0dfb7330ff8c5a181 │ my-vpc-01       │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ap-south-1     │ vpc-d74f60bf          │                 │
├────────────────┼────────────────┼───────────────────────┼─────────────────┤
│ Cloud-TME      │ ap-southeast-2 │ vpc-54aaf433          │                 │
╘════════════════╧════════════════╧═══════════════════════╧═════════════════╛


## Associate Tag

(venv) python3 cor-multicloud.py tag-hostvpc --input_yaml aws-config.yaml

Adding Tag to Host VPC

Successfully associated Tag VPC-Eng01 to Host VPC my-vpc-01

## Cloud Gateway list

(venv) python3 cor-multicloud.py cloud-gateway-list

Retrieving the MutliCloud Gateways
╒══════════════════════╤═══════════╤═════════════╤════════════════╤════════════════════╤══════════╕
│ Cloud Gateway Name   │   Site ID │ System IP   │ Reachability   │ Software Version   │ Status   │
╞══════════════════════╪═══════════╪═════════════╪════════════════╪════════════════════╪══════════╡
│ gcp-uswest-cgw1      │        56 │ 56.56.56.1  │ reachable      │ 17.07.01a.0.1883   │ normal   │
├──────────────────────┼───────────┼─────────────┼────────────────┼────────────────────┼──────────┤
│ gcp-uswest-cgw1      │        56 │ 56.56.56.2  │ reachable      │ 17.07.01a.0.1883   │ normal   │
╘══════════════════════╧═══════════╧═════════════╧════════════════╧════════════════════╧══════════╛

## Connected Sites

(venv) python3 cor-multicloud.py connected-sites

Retrieving the Connected Sites
╒═══════════════════╤═══════════╤════════════════╤═════════════════════╤════════════════╤═══════════════════╤══════════╕
│ Host name         │   Site ID │ Reachability   │ Software Version    │   BFD Sessions │   BFD Sessions Up │ Status   │
╞═══════════════════╪═══════════╪════════════════╪═════════════════════╪════════════════╪═══════════════════╪══════════╡
│ Megaport-Branch   │       100 │ reachable      │ 17.06.01a.0.298     │              4 │                 2 │ normal   │
├───────────────────┼───────────┼────────────────┼─────────────────────┼────────────────┼───────────────────┼──────────┤
│ Branch1-R1        │       111 │ reachable      │ 17.06.01prd21.0.79  │              4 │                 2 │ normal   │
├───────────────────┼───────────┼────────────────┼─────────────────────┼────────────────┼───────────────────┼──────────┤
│ Branch2-R1        │       112 │ reachable      │ 17.03.02prd9.0.3742 │              4 │                 2 │ normal   │
├───────────────────┼───────────┼────────────────┼─────────────────────┼────────────────┼───────────────────┼──────────┤
│ cl-cor-aws-usw1-2 │    128240 │ reachable      │ 17.05.01a.0.165     │              4 │                 2 │ normal   │
├───────────────────┼───────────┼────────────────┼─────────────────────┼────────────────┼───────────────────┼──────────┤
│ cl-cor-aws-usw1-1 │    128240 │ reachable      │ 17.05.01a.0.165     │              4 │                 2 │ normal   │
├───────────────────┼───────────┼────────────────┼─────────────────────┼────────────────┼───────────────────┼──────────┤
│ azu-uswest-cgw1   │    152240 │ reachable      │ 17.07.01a.0.1883    │              4 │                 2 │ normal   │
├───────────────────┼───────────┼────────────────┼─────────────────────┼────────────────┼───────────────────┼──────────┤
│ azu-uswest-cgw1   │    152240 │ reachable      │ 17.07.01a.0.1883    │              4 │                 2 │ normal   │
╘═══════════════════╧═══════════╧════════════════╧═════════════════════╧════════════════╧═══════════════════╧══════════╛