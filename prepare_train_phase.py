import numpy as np
import pandas as pd
import Vector_creator as Vc
import pickle
import time


df_object=pd.read_csv('train_dataset.csv',header=0)

training_df=pd.DataFrame(columns=('len_of_url','no_of_dots','security_sensitive_words','no_of_hyphens_in_dom',\
'dir_len','no_of_subdir','domain_len','domain_token_count','path_token_count','ip_present','largest_domain_tok_len',\
'avg_dom_token_len','largest_path_token_length','avg_path_token_length','suspicious tld','len_of_file','total_dots_in_file',\
'total_delims_in_file','len_of_argument','no_of_variables','len_of_largest_variable_val',\
'max_no_of_argum_delims','create_age(months)','expiry_age(months)','update_age(days)','zipcode'))


print('\n\n===========================================================')
print('Starting to Extract Training Data from URLs')
print('===========================================================\n\n')
print('And we go.....3,2,1')
time.sleep(3)


for i in range(len(df_object['URL'])):
	vec=Vc.Construct_Vector(df_object.URL[i])
	training_df.loc[i]=vec
	print('Training example :',i,"done")


training_df['Lable']=df_object.Lable
training_df['URL']=df_object.URL
del(df_object)

print('all done feature values for training set obtained')


print('\n\n==========================================================')
print('\nStarting to dump Training Data')
print('==========================================================\n\n')
training_df.to_csv('New_train_data.csv',index=False)
#pickle.dump(training_df,open('Training_Data_test.pkl','wb'))				###Writing the Information on a Binary File
print('All Done')
