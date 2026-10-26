"""Train XGBoost on train.csv, tune threshold on validation.csv, evaluate on test.csv."""
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (precision_score, recall_score, f1_score,
                              roc_auc_score, confusion_matrix)
import xgboost as xgb

train = pd.read_csv('train.csv')
val = pd.read_csv('validation.csv')
test = pd.read_csv('test.csv')

Xtr = train.drop(columns=['phishing']).values
ytr = train['phishing'].values
Xva = val.drop(columns=['phishing']).values
yva = val['phishing'].values
Xte = test.drop(columns=['phishing']).values
yte = test['phishing'].values

dtrain = xgb.DMatrix(Xtr, label=ytr)
dval = xgb.DMatrix(Xva, label=yva)
dtest = xgb.DMatrix(Xte, label=yte)

params = {
    'objective': 'binary:logistic',
    'eval_metric': 'auc',
    'max_depth': 6,
    'eta': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'scale_pos_weight': float((ytr==0).sum()/(ytr==1).sum()),
    'seed': 42,
}
bst = xgb.train(params, dtrain, num_boost_round=300,
                evals=[(dval,'val')], early_stopping_rounds=30, verbose_eval=50)

# Save in XGBoost JSON format compatible with inference.js (expects learner.gradient_booster.model)
bst.save_model('model.json')
print('saved model.json')

# Threshold sweep on validation
va_prob = bst.predict(dval)
best = None
for t in np.arange(0.1, 0.91, 0.01):
    pred = (va_prob >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(yva, pred).ravel()
    fpr = fp/(fp+tn) if (fp+tn) else 0
    fnr = fn/(fn+tp) if (fn+tp) else 0
    f1 = f1_score(yva, pred)
    # minimize FNR subject to FPR <= 0.02, then maximize F1
    if fpr <= 0.02:
        if best is None or fnr < best[1] or (fnr==best[1] and f1>best[2]):
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

# Write chosen threshold into a small file for reference
with open('threshold.txt','w') as f:
    f.write(str(round(float(t),2)))
print('threshold written to threshold.txt')
PY