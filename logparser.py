import re
import argparse
import logging
import sys
import time


''' This function will determine the OS '''
def determine_os(user_agent_str):
    if('windows phone' in user_agent_str.lower()):
        return 'Windows Phone'
    elif('windows' in user_agent_str.lower()):
        return 'Windows'
    elif('android' in user_agent_str.lower()):
        return 'Android'
    elif('ipad' in user_agent_str.lower() and 'iphone' in user_agent_str.lower()):
        return 'iOS'
    elif('macintosh' in user_agent_str.lower() or 'mac os' in user_agent_str.lower()):
        return 'MacOS'
    elif('linux' in user_agent_str.lower()):
        return 'Linux'
    else:
        return 'other'
    

'''process and print Stats'''
def processFile_and_printStats(file):
    logger=logging.getLogger(__name__)
    ''' initialize variables '''    
    lines_processed=0
    lines_processed_successfully=0
    request_stats_dict={}
    user_agent_stats_dict={}
    get_post_os_stats_dict={}
    
    '''open and process log file '''
    pattern = re.compile(r'[\d.]+ [\w.-]+ [\w.-]+ [[](?P<req_date>[^:]+):[^]]+[]] "(?P<http_method>\w+) [^\"]+" [\d]+ [\d]+ "[^\"]*" "(?P<user_agent>.*)"$')
    try:    
        with open(file,'r') as logfile:
            logger.debug("Opening File "+file)
            for line in logfile:
                lines_processed+=1

                
                logger.debug("Processing line#: {}".format(lines_processed))

                result = pattern.match(line)
        
                if(result is None):
                    logger.info("Ignoring Line#<{}> as pattern did not match expected regex pattern".format(lines_processed))
                    logger.debug("Line: {}".format(line))
                    continue
                                
                rdict=result.groupdict()
                
                try:
                    time.mktime(time.strptime(rdict['req_date'],"%d/%b/%Y"))
                except Exception as err:
                    logger.info("Ignoring Line#<{}> as date is invalid".format(lines_processed))
                    logger.info("Line: {}".format(line))
                    continue
                     
                
                req_date = rdict['req_date']
                http_method = rdict['http_method']
                user_agent = rdict['user_agent']
                
                
                ''' update statistics dictionaties '''
                
                '''request statistics by date keeps track of date wise statistics'''
                if(req_date not in request_stats_dict):
                    request_stats_dict[req_date]=1
                else:
                    request_stats_dict[req_date]+=1
                
                logger.debug("updated request Stats")
                
                ''' user_agent_stats_dict keeps track of user agent statistics by date '''
                if(req_date not in user_agent_stats_dict):
                    user_agent_stats_dict[req_date]={}
                
                if(user_agent not in user_agent_stats_dict[req_date]):
                    user_agent_stats_dict[req_date][user_agent]=1
                else:
                    user_agent_stats_dict[req_date][user_agent]+=1
                
                logger.debug("updated user agent stats")
                
                
                
                '''check if requets is GET or POST '''    
                if(http_method=='GET' or http_method=='POST' ):
                
                    '''the get and post os stats are tricky as os needs to be determined and is not always evident'''
                    client_os=determine_os(user_agent)
                    if(client_os is None):
                        logger.info("Could not determine os for user-agent string: {}".format(user_agent))
                        client_os='NA'
                    else:
                        logger.debug("user-agent: {} \tDetermined OS {}".format(user_agent,client_os))
                
                    '''update get and post statistics by date'''
                        
                    '''add req_date in both get and post since we don't want to be checking during ratios'''
                    if(req_date not in get_post_os_stats_dict):
                        get_post_os_stats_dict[req_date]={}
                        logger.debug("Adding date {}  to get_post_os_stats_dict".format(req_date))
                         
                    
                    if client_os not in get_post_os_stats_dict[req_date]:
                        get_post_os_stats_dict[req_date][client_os]={'GET': 0 , 'POST': 0}
                          
                                           
                    '''update get or post stats'''
                    if(http_method=='POST'):
                        get_post_os_stats_dict[req_date][client_os]['POST']+=1
                    
                    if(http_method=='GET'):
                        get_post_os_stats_dict[req_date][client_os]['GET']+=1
                    
                    logger.debug("updated GET/POST dictionary stats")
                    
                lines_processed_successfully+=1
                
                
                
    
        
        ''' Now Print Stats'''
        print("##################")
        print("Total Lines in File: {}".format(lines_processed))
        print("Total lines in File processed successfully: {}".format(lines_processed_successfully))
        print("###################")
        print("\n")
        
        print("TotalRequests by Date")
        for i in sorted(request_stats_dict.keys(),key=lambda x: time.mktime(time.strptime(x,"%d/%b/%Y"))):
            print("{:12s} -> {:8d}".format(i,request_stats_dict[i]))
    
        print("\n#####################")
        print("Top 3 user-agent-strings seen in requests")
        for i in sorted(user_agent_stats_dict.keys(),key=lambda x: time.mktime(time.strptime(x,"%d/%b/%Y"))):
            print("Request Date is {:12s} -".format(i))
            for x,v in sorted( user_agent_stats_dict[i].items(),key=lambda x: x[1], reverse=True )[:3]:
                print("\t {:90s} -> {:5d}".format(x,v))
            print("\n")
        
        
        print("\n#####################")
        print("OS GET/PUT Ratio seen in requests")
        for i in sorted(get_post_os_stats_dict.keys(),key=lambda x: time.mktime(time.strptime(x,"%d/%b/%Y"))):
            print("Request Date is {:12s} -".format(i))
            for os in get_post_os_stats_dict[i]:
                if(get_post_os_stats_dict[i][os]['POST'] == 0):
                    ratio = "INFINITY"
                    print("\t OS:{:15s} GET: {:5d} POST: {:5d} GET/PUT Ration: {:5s}".format(os,get_post_os_stats_dict[i][os]['GET'],get_post_os_stats_dict[i][os]['POST'],'INFINITY'))                  
                else:
                    ratio = get_post_os_stats_dict[i][os]['GET']/get_post_os_stats_dict[i][os]['POST']
                    print("\t OS:{:15s} GET: {:5d} POST: {:5d} GET/PUT Ration: {:5f}".format(os,get_post_os_stats_dict[i][os]['GET'],get_post_os_stats_dict[i][os]['POST'],ratio))
            
        
    except Exception as errmsg:
        print("exiting")
        print(str(errmsg))
        exit(1)
        
    

def main():
    
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    
    ''' Parse Arguments and set logging level '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',required=False,action='store_true')
    parser.add_argument('-f','--logfile',required=True)
    args = parser.parse_args()
    logger = logging.getLogger(__name__)
        
    if(args.verbose):
            logger.setLevel(logging.DEBUG)
    

    logger.debug("Arguments: LogFile: "+args.logfile+"\tVerbose Mode: "+str(args.verbose))
        
    try:
        if(not args.logfile.startswith("/") and not args.logfile.startswith("./")):
            args.logfile="./"+args.logfile
        
        '''process and print stats'''
        processFile_and_printStats(args.logfile)
                        
    except Exception as e:
        logger.error(str(e))
        exit(1)
    
if __name__ == '__main__':
    main()