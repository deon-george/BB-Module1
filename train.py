"""Train XGBoost on PhishingDataset.csv, tune threshold on validation, evaluate on test."""
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score, f1_score,
                              roc_auc_score, confusion_matrix)
import xgboost as xgb

df = pd.read_csv('PhishingDataset.csv')
# Result: 1 = phishing, -1 = legitimate
y = (df['Result'] == 1).astype(int).values
X = df.drop(columns=['Result']).values
feature_names = list(df.drop(columns=['Result']).columns)

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
Xtr, Xva, ytr, yva = train_test_split(Xtr, ytr, test_size=0.25, random_state=42, stratify=ytr)

dtrain = xgb.DMatrix(Xtr, label=ytr, feature_names=feature_names)
dval = xgb.DMatrix(Xva, label=yva, feature_names=feature_names)
dtest = xgb.DMatrix(Xte, label=yte, feature_names=feature_names)

params = {
    'objective': 'binary:logistic',
    'eval_metric': 'auc',
    'max_depth': 6,
    'eta': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'scale_pos_weight': float((ytr == 0).sum() / (ytr == 1).sum()),
    'seed': 42,
}
bst = xgb.train(params, dtrain, num_boost_round=300,
                evals=[(dval, 'val')], early_stopping_rounds=30, verbose_eval=50)

bst.save_model('model.json')
print('saved model.json')

va_prob = bst.predict(dval)
best = None
for t in np.arange(0.1, 0.91, 0.01):
    pred = (va_prob >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(yva, pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0
    f1 = f1_score(yva, pred)
    if fpr <= 0.02:
        if best is None or fnr < best[1] or (fnr == best[1] and f1 > best[2]):
            best = (t, fnr, f1, fpr)
print('best threshold (FPR<=0.02):', best)

t = best[0] if best else 0.5
print('using threshold', t)

def report(name, y, p, t):
    pred = (p >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    print(f'[{name}] thr={t:.2f} acc={(pred==y).mean():.4f} prec={precision_score(y,pred):.4f} rec={recall_score(y,pred):.4f} f1={f1_score(y,pred):.4f} auc={roc_auc_score(y,p):.4f} FPR={fp/(fp+tn):.4f} FNR={fn/(fn+tp):.4f}')

report('validation', yva, va_prob, t)
te_prob = bst.predict(dtest)
report('test', yte, te_prob, t)

with open('threshold.txt', 'w') as f:
    f.write(str(round(float(t), 2)))
print('threshold written to threshold.txt')