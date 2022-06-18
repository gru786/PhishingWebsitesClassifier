
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn import tree
#from sklearn.externals import joblib
import joblib
from sklearn.metrics import accuracy_score

def d():
    dataset = pd.read_csv("phishcoop.csv")
    dataset = dataset.drop('id', 1) #removing unwanted column
    x = dataset.iloc[ : , :-1].values
    y = dataset.iloc[:, -1:].values

    #spliting the dataset into training set and test set
    from sklearn.model_selection import train_test_split
    x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state =0 )

    #fitting logistic regression 
    classifier = tree.DecisionTreeClassifier() 
    classifier.fit(x_train, y_train)

    #predicting the tests set result
    y_pred = classifier.predict(x_test)
    print(accuracy_score(y_test, y_pred))
    #confusion matrix
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    #pickle file joblib
    joblib.dump(classifier, 'final_models/dt.pkl')

