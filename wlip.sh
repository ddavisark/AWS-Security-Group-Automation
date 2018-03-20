#################################################################
#
# Description: Script to update Pingdom IP addresses
# Author: David Davis
# Date: 17 Feb 2018
#

# Always set your shell

#!/bin/bash
. ~/.profile

cdir=`pwd`
if [ ! -d $cdir/logs ]
then
   mkdir $cdir/logs
fi

LOCK=/var/tmp/mylock
if [ -f $LOCK ]
then
   echo "The script is currently running...wait your turn."
   rm $LOCK
   sleep 2
   exit 6
fi
touch $LOCK

type=$1
YEAR=`date +%Y`
MONTH=`date +%m`
DAY=`date +%d`
HOUR=`date +%H`
MINUTE=`date +%M`
SECOND=`date +%S`
TS=${YEAR}${MONTH}${DAY}${HOUR}${MINUTE}
LOG=$cdir/logs/audit.log
progname=$(printf '%s\n' "${0##*/}")
IPV4="/tmp/ipv4.txt"
IPS="/tmp/ips.txt"
CITY="/tmp/city.txt"
COUNTRY="/tmp/country.txt"
CITYASCII="/tmp/cityascii.txt"
COUNTRYASCII="/tmp/countryascii.txt"
LIST="/tmp/list.txt"
IPCIDR="$cdir/ipcidr.txt"
IPCIDROLD="$cdir/ipcidr.old"
IPADD="/tmp/ipadd.txt"
IPDELETE="/tmp/ipdelete.txt"
DIFFFILE="/tmp/difffile.txt"
CONTENTS="/tmp/contents"
CURRENTIPS="/tmp/currentips"
ACTIVE="/tmp/active.txt"
SUMMARY="$cdir/logs/summary.log"
SFPrefix="ipdata"
RuleMax=45
IpTotal=0

#############################################################
#
# GetSgCount()
#
# Obtain the security group count and return the value 
# 

function GetSgCount()
{
   local sgcount

   sgcount=`aws ec2 describe-security-groups --filters Name=group-name,Values="'"$SGNamePrefix*"'"\
     --query 'SecurityGroups[*].{Name:GroupName}' | grep Name| awk '{print $2}'|\
     sed 's/"//;s/".*//'|wc -l`
   echo $sgcount
}

#############################################################
#
# GetSgPrefix()
#
# Get the first 4 characters of the default whitelisting
# security group and return the 4 char string  
# 

function GetSgPrefix()
{
   local SGPrefixName

   SGPrefixName=`aws ec2 describe-network-interfaces |grep GroupName|grep -v 'ssh'|\
     awk '{print $2}'|sed 's/"//;s/".*//'|cut -c1-4`
#   SGPrefixName="Prot"
   echo $SGPrefixName
}

#############################################################
#
# GetDefaultSg()
#
# Get the entire default security group for whitelisting 
# and return the string

function GetDefaultSg()
{
   local SGDefault

   SGDefault=`aws ec2 describe-instances --output text|grep SECURITYGROUPS|grep -v ssh|awk '{print $2}'`
   echo $SGDefault
}

#############################################################
#
# GetVpcId()
#
# Get the vpcid from the network interfaces instance and
# return the value 
#

function GetVpcId()
{
   local vpcid

   vpcid=`aws ec2 describe-network-interfaces |grep 'VpcId'| awk '{print $2}'|uniq|sed 's/"//;s/".*//'`
   echo $vpcid
}

#############################################################
#
# CreateSg()
#
# Create a security group and return the associated groupid 
# 

function CreateSg()
{
   local groupid

   VpcId=$(GetVpcId)
   grpname=$(GetSgBaseName)
   groupid=`aws ec2 create-security-group --group-name "${grpname}-${1}" --description\
            "Whitelisted Firewall IPs" --vpc-id ${VpcId}|\
            grep "Id"|awk '{print $2}'|sed 's/"//;s/".*//'`
   echo $groupid
}

#############################################################
#
# DeleteSg()
# 
# Delete the security group as needed, returned value of 0
# for success, 1-127 indicates an error occurred. 
#

DeleteSg()
{
   aws ec2 delete-security-group --group-id ${1}\
     echo -e "$1 \t$2 \treturn code: $?"| grep 'return code' >> delsecgrp.out
}

#############################################################
#
# GetNeededSgCount()
#
# Calculate the number of security groups needed based on
# the constant RuleMax value given the number of IPs needing
# to be stored and return the count of security groups needed
#

function GetNeededSgCount()
{
   local groupcount 

   for ctr in {1..10}
   do
      product=$((RuleMax * $ctr))
      if [[ $IpTotal -lt $product && $IpTotal -gt $prevproduct ]]
      then
         groupcount=$ctr
      fi
      prevproduct=$product
   done
   echo $groupcount
}

#############################################################
#
# GetSgBaseName()
#
# Get the basename of the security group give the 4 char
# prefix and return the basename string 
#

function GetSgBaseName()
{
   local basename

   basename=`aws ec2 describe-security-groups --filters Name=group-name,Values="'"$SGNamePrefix*"'"\
     --query 'SecurityGroups[*].{Name:GroupName}'|grep 'Name'|sed 's/.* "//;s/".*//'|sed 's/-.*//'|uniq`
   echo $basename
}

#############################################################
#
# GetSgLast()
#
# Get the last ordinally ranked security groups so it can
# be removed.  Return the lastname group string. 
#

function GetSgLast()
{
   local lastgroup

   lastgroup=`aws ec2 describe-security-groups --filters Name=group-name,Values="'"$SGNamePrefix*"'"\
     --query 'SecurityGroups[*].{Name:GroupName}'| grep Name|awk '{print $2}'|\
     sed 's/"//;s/".*//'|sort|tail -n1`
   echo $lastgroup
}

#############################################################
#
# GetSgId()
#
# Get the security group id associated with the groupname and
# return the groupid 
#

function GetSgId()
{
   local sgid

   sgid=`aws ec2 describe-security-groups --filters Name=group-name,Values="'"$1"'"\
     --query 'SecurityGroups[*].{ID:GroupId}'|grep ID|sed 's/.* "//;s/".*//'`
   echo $sgid
}

#############################################################
#
# Usage()
#
# Display the lines to stdout when a failad arg is entered
# from the command line

Usage()
{
   echo ""
   echo "Usage: <absolute path>/$progname {full | incremental}"
   echo ""
   echo "Refresh Type:"
   echo ""
   echo -e "\tfull: Performs a total refresh of all security groups"
   echo -e "\tincremental: Performs difference from current IP list vs previous IP list downloaded"
   echo ""
}

#############################################################
#
# GetSecurityGroups()
#
# Retrieve the security group ids with group names beginning
# with SGNamePrefix to load the SecurityGroup array
#

GetSecurityGroups()
{
   # First get the prefix of the Pingdom security groups name

   SGNamePrefix=$(GetSgPrefix)
   vlist=`aws ec2 describe-security-groups --filters Name=group-name,Values="'"$SGNamePrefix*"'" --query\
    'SecurityGroups[*].{Name:GroupName,ID:GroupId}'|grep 'ID'|sed 's/.* "//;s/".*//'`
   SecurityGroups=($vlist)
}

#############################################################
#
# GetPingdomIPv4Addresses()
#
# Obtain server.xml file from Pingdom web site
#

GetPingdomIPv4Addresses()
{
   # Obtain the server.xml file from Pingdom
   wget --quiet -O- https://www.pingdom.com/rss/probe_servers.xml > $IPV4

   # Check if the file has data, if not then exit
   if [ ! -s $IPV4 ]
   then
      echo -e "${TS}\tThe server.xml file not available from Pingdom" >> $LOG
      rm $LOCK
      sleep 2
      exit 1
   fi

   # Obtain active Pingdom IPs
   grep 'description>IP:' $IPV4| grep 'Active' > $ACTIVE

   # Parse active to get all the current Active Pingom sites
   cat $ACTIVE| sed 's/.*IP: //;s/;.*//' > $IPS

   # Parse active to get the associated country of the IP
   cat $ACTIVE| sed 's/.*Country: //;s/;.*//' > $COUNTRY 

   # Parse active to get the associated city of the IP and country
   cat $ACTIVE| sed 's/.*City: //;s/<.*//' > $CITY

   # Concatenate /32 to each IP in the ips file
   sed 's/$/\/32/' $IPS > $IPCIDR

   iconv -f utf-8 -t ascii//translit < $CITY > $CITYASCII
   iconv -f utf-8 -t ascii//translit < $COUNTRY > $COUNTRYASCII

   # Create a temp file have 3 columns (ips city country) for later use
   # and ease
   paste -d':' $IPCIDR $CITYASCII $COUNTRYASCII > $LIST
   rm $ACTIVE $IPS $CITY $COUNTRY $CITYASCII $COUNTRYASCII $IPV4
}

#############################################################
#
# FullRefreshInit()
#
# Get the number of IPs to load, build the files necessary
# for import and determine count of existing security groups
# plus the number of security groups needed for the import
# and adjust the security group count as needed.  
#

FullRefreshInit()
{
   # Get a count of lines from SLIST because a security group
   # can only store RuleMax rule count

   IpTotal=`cat $LIST |wc -l`
   split -d -l $RuleMax $LIST $SFPrefix
   datalist=`ls $SFPrefix*`
   data=($datalist) 

   # Get a count of files that were split, that will determine the number
   # of security groups needed
   sgneeded=${#data[@]}

   # Now find out how many security groups currently exist
   SGNamePrefix=$(GetSgPrefix)
   GetSecurityGroups
   sgexist=$(GetSgCount)

   if [ $sgneeded -ne $sgexist ]
   then
      if [ $sgneeded -gt $sgexist ]
      then
         for ((ctr=$((sgexist+1)); ctr <= $sgneeded; ctr++))
         do 
            sgid=$(CreateSg $ctr)
            SecurityGroups=( "${SecurityGroups[@]}" "${sgid}" )
         done
      elif [ $sgexist -gt $sgneeded ]
      then
         for ((ctr=1; ctr<=$((sgexist-sgneeded)); ctr++))
         do
            last=$(GetSgLast)
            id=$(GetSgId $last)
            DeleteSg ${id}
            SecurityGroups=( ${SecurityGroups[@]/${id}/} )
         done
      fi
   fi
}

#############################################################
#
# GetSgRuleIPs()
#
# Obtain the current IPs from each security group
#

GetSgRuleIPs()
{
   aws ec2 describe-security-groups --group-id $1 | grep CidrIp | grep -v "::/0\|0.0.0.0/0" |\
    sed 's/.*"CidrIp": "//;s/".*//' > $CURRENTIPS.${1}
   rulecount=`cat $CURRENTIPS.${1} |wc -l`
}

#############################################################
#
# DeleteSgRules()
#
# Remove the IP and associate Json string from each security group
#

DeleteSgRules()
{
   aws ec2 revoke-security-group-ingress --group-id ${1} --protocol tcp --port 80 --cidr $2;\
      echo -e "$1 \t$2 \treturn code: $?"| grep 'return code' >> revoke.out
}

#############################################################
#
# InsertSgRules()
#
# Add the IP rule back into each security group
#

InsertSgRules()
{
   aws ec2 authorize-security-group-ingress --group-id $1 --ip-permissions\
      '[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "'"${2}"'", "Description": "'"${3}"'"}]}]';\
      echo -e "$1 \t$2 \treturn code: $?"| grep 'return code' >> ingress.out
}

#############################################################
#
# SummaryDetails()
#
# Provides a summary in table format of the full operation 
#

SummaryDetails()
{
   echo "Date: ${MONTH}/${DAY}/${YEAR}" | tee -a $SUMMARY
   echo "" | tee -a $SUMMARY
   echo "Total IPs Imported: $IpTotal" | tee -a $SUMMARY
   echo "" | tee -a $SUMMARY

   for sg in ${SecurityGroups[@]}
   do
      REVSUCCESS=`cat revoke.out | grep $sg | grep -w 'return code: 0' | wc -l`
      REVFAILURE=`cat revoke.out | grep $sg | grep -v 'return code: 0' | wc -l`
      INGSUCCESS=`cat ingress.out | grep $sg | grep -w 'return code: 0' | wc -l`
      INGFAILURE=`cat ingress.out | grep $sg | grep -v 'return code: 0' | wc -l`

      echo -e "Service Group ${sg} Results" | tee -a $SUMMARY
      echo "" | tee -a $SUMMARY
      echo -e "\t- Revoked Success......: $REVSUCCESS" | tee -a $SUMMARY
      echo -e "\t- Revoked Failure......: $REVFAILURE" | tee -a $SUMMARY
      echo -e "\t- Ingress Success......: $INGSUCCESS" | tee -a $SUMMARY
      echo -e "\t- Ingress Failure......: $INGFAILURE" | tee -a $SUMMARY
      head -1 ${sg}.time | tee -a $SUMMARY
      tail -1 ${sg}.time | tee -a $SUMMARY
      echo "" | tee -a $SUMMARY
   done
}

#############################################################
#
# IncrementalOperation()
#
# Check the incomimng ACTIVE IPs from Pingdom and compare
# against the previously download IP file.  If the same,
# then the IPs loaded are in Sync with Pingdom, else add or
# delete from the repository as needed. 
#

IncrementalOperation()
{
   SGNamePrefix=$(GetSgPrefix)
   GetSecurityGroups

   for sg in ${SecurityGroups[@]}
   do
      aws ec2 describe-security-groups --group-id ${sg} > $CONTENTS.${sg}
   done

   if [ ! -f $IPCIDROLD ]
   then
      cp $IPCIDR $IPCIDROLD
   fi

   chg=`diff -s $IPCIDROLD $IPCIDR`

   # If files are identical then log the operation and move the new ip file to
   # the previous file ipcidr.old

   if [[ $chg == *"identical"* ]]
   then
      echo -e "${TS}Z\tINCR Refresh Performed" >> $LOG
      mv $IPCIDR $IPCIDROLD
   else
      # The IP files, current and previous are different, so do a compare
      touch $DIFFFILE
      diff $IPCIDROLD $IPCIDR > $DIFFFILE

      # Search the file output from the diff comparison and if a '<' character
      # is found, then Pingdom has removed a site.  Whereas should a '>' be
      # found then Pingdom has added a new site IP.  The operation on each grep
      # redirects the IP to either file IpDelete or IpAdd...

      grep '< ' $DIFFFILE|sed 's/.*< //' > $IPDELETE
      grep '> ' $DIFFFILE|sed 's/.*> //' > $IPADD

      if [ -s $IPDELETE ]
      then
         while read ip
         do
            sgrp=`grep ${ip} $CONTENTS.sg-*|sed "s#$CONTENTS\.##;s#:.*##"`
            DeleteSgRules $sgrp $ip
            echo -e "${TS}Z\t${sgrp}\tREVOKE\t${ip}" >> $LOG
         done < $IPDELETE
         rm $IPDELETE
      fi

      # Should IpAdd have data then add to a security group that has a count less than $RuleMax 

      if [ -s $IPADD ]
      then
         while read ip
         do
            # Find a security group that has less than RuleMax entries
            insert=1
            for sg in ${SecurityGroups[@]}
            do
               count=`aws ec2 describe-security-groups --group-id ${sg} |\
                 grep -v "0.0.0.0\/0"|grep -c 'CidrIp'`

               if [ "$count" -lt "$RuleMax" ] && [ $insert -eq 1 ]
               then
                  line=`grep $ip $LIST`
                  desc=`echo $line | awk -F':' '{print "Ping Site - " $2",",  $3}'`
                  InsertSgRules ${sg} ${ip} "${desc}"
                  insert=0
                  echo -e "${TS}Z\t${sg}\tINSERT\t${ip}" >> $LOG
               fi
            done

            # Should all of the security groups be "maxed out in count" then create
            # a new security group.

            if [ $insert -eq 1 ]
            then
               seccount=$(GetSgCount)
               seccount=$((seccount+1))
               sgid=$(CreateSg $seccount)
               SecurityGroups=( "${SecurityGroups[@]}" "${sgid}" ) 
               line=`grep $ip $LIST`
               desc=`echo $line | awk -F':' '{print "Ping Site - " $2",",  $3}'`
               InsertSgRules ${sgid} ${ip} "${desc}"
               insert=0
               echo -e "${TS}Z\t${sgid}\tINSERT\t${ip}" >> $LOG
            fi
         done < $IPADD
         rm $IPADD
      fi
      mv $IPCIDR $IPCIDROLD
   fi

   # Cleanup time, remove tmp files
   if [ -f $DIFFFILE ]
   then
      rm $DIFFFILE
   fi
   rm $LIST $CONTENTS.*
}

#############################################################
#
# FullRefreshOperation()
#
# Loop through each security group and remove each rule and then
# add with the new IPs just downloaded. 
#

FullRefreshOperation()
{
   # Full refresh block

   touch ingress.out
   touch revoke.out
   rulecount=0

   for index in ${!SecurityGroups[*]}
   do
      touch ${SecurityGroups[$index]}.time
      HOUR=`date +%H`
      MINUTE=`date +%M`
      SECOND=`date +%S`
      echo -e "\t- Start................: ${HOUR}:${MINUTE}:${SECOND}" > ${SecurityGroups[$index]}.time

      # Obtain the IPs from all 3 security groups
          
      GetSgRuleIPs ${SecurityGroups[$index]} 

      if [ $rulecount -gt 0 ]
      then
         while read ip
         do
            # Delete the IP rules found in the security group
            DeleteSgRules ${SecurityGroups[$index]} $ip
            sleep .25 
         done < $CURRENTIPS.${SecurityGroups[$index]}
      fi

      while read line
      do
         ip=`echo $line |awk -F':' '{print $1}'`
         desc=`echo $line | awk -F':' '{print "Ping Site - " $2",",  $3}'`
         InsertSgRules ${SecurityGroups[$index]} ${ip} "${desc}"
         sleep .25 
      done < ${data[$index]}

      rulecount=0
      HOUR=`date +%H`
      MINUTE=`date +%M`
      SECOND=`date +%S`
      echo -e "\t- Completion...........: ${HOUR}:${MINUTE}:${SECOND}" >> ${SecurityGroups[$index]}.time
      echo ""
   done

   # Move the current IP file to old to satisfy the next execution of the script

   mv $IPCIDR $IPCIDROLD

   # Write to the audit log 

   echo -e "${TS}Z\tFULL Refresh Performed" >> $LOG
   rm $LIST $CURRENTIPS.* $SFPrefix*
   SummaryDetails
   rm *.time

   # Maintain history of transactions since last full refresh

   mv $cdir/ingress.out $cdir/logs/ingress.log
   mv $cdir/revoke.out $cdir/logs/revoke.log

   # Backup logs daily

   gzip -c -- `find $cdir/logs -type f -name "*.log"` > $cdir/archive/logs.${YEAR}${MONTH}${DAY}.gz
   :>| $HOME/proto/logs/audit.log
   :>| $HOME/proto/logs/summary.log
   rm $HOME/proto/logs/ingress.log
   rm $HOME/proto/logs/revoke.log
}

####################################################################################
#
# Main routine
#

# Check command line input, if missing arg then exit or should the arg not
# equal incremental or full also exit and display the Usage info

if [ -z $1 ]
then
    Usage 
    rm $LOCK
    sleep 1
    exit 1
elif [[ "${1}" != +(incremental|full) ]]
then
    Usage
    rm $LOCK
    sleep 1
    exit 1
fi

if [ $RuleMax -gt 50 ]
then
   echo "The RuleMax value must be less than 50, suggested value is 45"
   rm $LOCK
   sleep 2
   exit 1
fi

GetPingdomIPv4Addresses

if [ $type == "full" ]
then
   FullRefreshInit
   FullRefreshOperation
else # type is incremental
   IncrementalOperation
fi

rm $LOCK
