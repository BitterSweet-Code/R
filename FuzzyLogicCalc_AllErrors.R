# Fuzzy Model

# Libraries Required
library(sets)

# Create a universe 
# This is the domain of values (from the Likert Scale)
sets_options("universe", seq(from = -2, to = 2, by = 0.001))

# get_error_rules : function 
# params : 
#   error_name : A string that is one of the following 
#                      "unintentional_disclosure"
#                      "missing_updates"
#                      "access_org_personal_dev"
#                      "poor_password_practices"
#                      "phishing"
#                      "unintended_recipient" 
#                      "malware_ransomware" 
#                      "loss_paperwork_storage_device" 
#                      "not_backing_up_data" 
#                      "carrying_out_unfamiliar_actions_without_supervision"
#                      "leaving_devices_unattended" 
#                      "sharing_identifiable_information_on_social_media" 
#                      "popups_scam_website" 
#                      "unauthorized_device_access"
# returns : a fuzzy rules function corresponding to the input error

get_error_rules <- function (error_name){
  unintentional_disclosure <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  missing_updates <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                         fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                         fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  access_org_personal_dev <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low))
  poor_password_practices <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                 fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low))
  
  phishing <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                  fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                  fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  unintended_recipient <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
          
  malware_ransomware <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                            fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                            fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  loss_paperwork_storage_device <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                       fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                       fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high))
  
  
  not_backing_up_data <- set (fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                              fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                              fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  Carrying_out_unfamiliar_actions_without_supervision <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                                                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low))
  
  
  
  Leaving_devices_unattended <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                                    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  
  
  
  Sharing_identifiable_information_on_social_media <- set(
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% low),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% high),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high))
  
  
  
  
  Popups_Scam_Website <- set(fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% low),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                             fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% high),
                             fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  
  unauthorized_device_access <- set(
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% high),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% medium),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% high),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% medium),
    fuzzy_rule(CONS %is% c_low && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% high),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_low, p_error %is% low),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_low && APT %is% p_high, p_error %is% medium),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_low, p_error %is% low),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_low && ATT %is% t_high && APT %is% p_high, p_error %is% low),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_low, p_error %is% medium),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_low && APT %is% p_high, p_error %is% high),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_low, p_error %is% low),
    fuzzy_rule(CONS %is% c_high && AGREE %is% a_high && ATT %is% t_high && APT %is% p_high, p_error %is% medium))
  
  # Encapsulate all of the 14 errors into a list 
  
  error_funcs <- list("unintentional_disclosure" = unintentional_disclosure, 
                      "missing_updates" = missing_updates, 
                      "access_org_personal_dev" = access_org_personal_dev, 
                      "poor_password_practices" =poor_password_practices, 
                      "phishing" = phishing, 
                      "unintended_recipient" =unintended_recipient, 
                      "malware_ransomware" = malware_ransomware, 
                      "loss_paperwork_storage_device" = loss_paperwork_storage_device, 
                      "not_backing_up_data" = not_backing_up_data,
                      "carrying_out_unfamiliar_actions_without_supervision"=Carrying_out_unfamiliar_actions_without_supervision,
                      "leaving_devices_unattended" = Leaving_devices_unattended,
                      "sharing_identifiable_information_on_social_media" = Sharing_identifiable_information_on_social_media, 
                      "popups_scam_website" = Popups_Scam_Website,
                      "unauthorized_device_access" = unauthorized_device_access)
  # Search for the queried error 
  # and return it 
  return(error_funcs[[error_name]])
}

# get_error_probabilities : function 
# params : 
#         error : A string for each of the errors we want the probability for
#         cons : Conscientiousness score [-2,2]
#         agree : Agreeableness score [-2,2]
#         att : Attitude [-2,2]
#         apt : Aptitude [-2,2]

get_error_probabilities <- function (error, cons, agree, att, apt){
  # Input the membership and domain 
  # of the variables
  variables <- set(
    CONS = fuzzy_variable(c_high =
                            fuzzy_trapezoid(corners = c(-1, 1, 2, 3)),
                          c_low =
                            fuzzy_trapezoid(corners = c(-3, -2, -1, 1))),
    AGREE = fuzzy_variable(a_high =
                             fuzzy_trapezoid(corners = c(-1, 1, 2, 3)),
                           a_low =
                             fuzzy_trapezoid(corners = c(-3, -2, -1, 1))),
    APT = fuzzy_variable(p_high =
                           fuzzy_trapezoid(corners = c(-1, 1, 2, 3)),
                         p_low =
                           fuzzy_trapezoid(corners = c(-3, -2, -1, 1))),
    ATT = fuzzy_variable(t_high =
                           fuzzy_trapezoid(corners = c(-1, 1, 2, 3)),
                         t_low =
                           fuzzy_trapezoid(corners = c(-3, -2, -1, 1))),
    p_error = fuzzy_variable(low =
                               fuzzy_sigmoid_gset(cross = 30, slope= -1, universe=seq(0,100,0.5)),
                             medium =
                               fuzzy_normal_gset(mean=50, sd=10, universe=seq(0,100,0.5)),
                             high =
                               fuzzy_sigmoid_gset(cross = 70, slope= 1, universe=seq(0,100,0.5))))
  
  # Input 4 variables into the fuzzy system 
  # Also input the error table retrieved from get_error_rules
  system <- fuzzy_system(variables, get_error_rules(error))
  
  # Create the inference using the user's data
  fi <- fuzzy_inference(system, list(CONS=cons, AGREE=agree, ATT=att, APT=apt))
  
  # Return the error using the centroid method
  return (gset_defuzzify(fi, "centroid"))
  
}

# Get Error Probabilties

# Example calculation for a user we think is exposed to Phishing 
# format for running the code is as follows
# get_error_probabilities ("ERROR_NAME", cons=_, agree=_, apt=_, att=_)

get_error_probabilities("phishing", cons=1, agree=0, apt=2, att=2)




