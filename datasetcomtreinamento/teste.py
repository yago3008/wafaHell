import joblib
model = joblib.load("random_forest.joblib")
print(type(model))
print(model)