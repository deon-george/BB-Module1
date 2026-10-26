/**
 * Local XGBoost inference for the BB-Extension Module1 phishing model.
 *
 * Reads backend/model.json (a 300-tree binary:logistic XGBClassifier) and
 * reproduces predict_proba exactly: margin = base_score_logit + sum(leaf
 * values); probability = sigmoid(margin).
 *
 * Tree traversal: at a split node, if x[split_index] < split_condition go
 * left, otherwise right. A node whose left_children == -1 is a leaf; its
 * base_weights value is the leaf contribution.
 */

const DEFAULT_BASE_SCORE = 0.52259356;
const BASE_LOGIT = Math.log(DEFAULT_BASE_SCORE / (1 - DEFAULT_BASE_SCORE));

let _model = null;
let _trees = null;
let _baseLogit = BASE_LOGIT;

/** Load and parse model.json into traversal-ready structures. */
async function loadModel(modelUrl) {
  const res = await fetch(modelUrl);
  if (!res.ok) {
    throw new Error(`Failed to load model: ${res.status} ${res.statusText}`);
  }
  const raw = await res.json();
  const learner = raw.learner;
  const gb = learner.gradient_booster;
  const model = gb.model;
  const baseScoreText = learner.learner_model_param?.base_score;
  const baseScore = baseScoreText
    ? Number(String(baseScoreText).replace(/[\[\]]/g, '').split(',')[0])
    : DEFAULT_BASE_SCORE;
  if (Number.isFinite(baseScore) && baseScore > 0 && baseScore < 1) {
    _baseLogit = Math.log(baseScore / (1 - baseScore));
  }
  const trees = model.trees.map((t) => ({
    left: t.left_children,
    right: t.right_children,
    splitIndex: t.split_indices,
    splitCondition: t.split_conditions,
    leafValue: t.base_weights,
  }));
  _model = raw;
  _trees = trees;
  return {
    numTrees: trees.length,
    numFeature: Number(
      learner.learner_model_param?.num_feature ||
      model.trees[0]?.tree_param?.num_feature ||
      0
    ),
  };
}

function _sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

function _traverse(tree, x) {
  let node = 0;
  const { left, right, splitIndex, splitCondition, leafValue } = tree;
  while (left[node] !== -1) {
    const idx = splitIndex[node];
    const cond = splitCondition[node];
    if (x[idx] < cond) {
      node = left[node];
    } else {
      node = right[node];
    }
  }
  return leafValue[node];
}

/**
 * Predict phishing probability for a 111-feature vector.
 * Returns { probability (0..1), margin }.
 */
function predict(featureVector) {
  if (_trees === null) {
    throw new Error('Model not loaded. Call loadModel() first.');
  }
  const x = featureVector;
  let margin = _baseLogit;
  for (let i = 0; i < _trees.length; i++) {
    margin += _traverse(_trees[i], x);
  }
  const probability = _sigmoid(margin);
  return { probability, margin };
}

/** Convenience: category + confidence like the backend. */
function classify(probability) {
  const predicted = probability >= 0.5 ? 1 : 0;
  return {
    category: predicted === 1 ? 'High Threat' : 'Legitimate',
    confidence: predicted === 1 ? probability : 1 - probability,
    predictedClass: predicted,
  };
}

export { loadModel, predict, classify, BASE_LOGIT };
