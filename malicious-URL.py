"""
This Module is the Neural Network Implementation of the Classfier using Tensorflow Learning API
"""
import numpy as np
## Importing TensorFlow API
import tensorflow as tf
import keras
import pickle as pkl
import Vector_creator as Vc
import pandas as pd
import collections
from sklearn.model_selection import train_test_split

#train_data=pkl.load(open('Training_Data.pkl','rb'))
#train_data = pd.read_pickle('Training_Data2.pkl')
train_data = pd.read_csv('New_train_data.csv')
print('\n\n===========================================================')
print('\nReading of Training Phase Done\n')
print('===========================================================\n\n')

y=train_data['Lable'].values						#### Stroring Training Lables 
x=train_data.drop(['URL','Lable'],axis=1).values	#### Droping Unecessary Columns from the Data Fram

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 0)

from sklearn.preprocessing import StandardScaler
sc = StandardScaler()

x_train = sc.fit_transform(x_train)
x_test = sc.transform(x_test)

print(x[0])

ann = tf.keras.models.Sequential()
ann.add(tf.keras.layers.Dense(units=10, activation = "relu"))
#ann.add(tf.keras.layers.Dense(units=8, activation = "relu"))
ann.add(tf.keras.layers.Dense(units=2, activation = "softmax"))

ann.compile(optimizer = 'rmsprop', loss = 'sparse_categorical_crossentropy', metrics = ['accuracy'])
ann.fit(x_train, y_train, batch_size = 32, epochs = 10)

y_pred = ann.predict(x_test)
#y_pred
y_pred = y_pred[:,1]

y_pred = ( y_pred > 0.5 )
print(np.concatenate((y_pred.reshape(len(y_pred),1), y_test.reshape(len(y_test),1)),1))

from sklearn.metrics import confusion_matrix, accuracy_score

cm = confusion_matrix(y_test, y_pred)
print(cm)
print("Accuracy: ", accuracy_score(y_test, y_pred)*100)

while True:
    url = input("Enter URL: ")
    if url == '':
        break
    vec=Vc.Construct_Vector(url)
    vec=np.array(vec)
    vec=vec.reshape(1,-1)
    result = ann.predict(vec)
    result = ( result[:,1] > 0.5 )
    print(result)


