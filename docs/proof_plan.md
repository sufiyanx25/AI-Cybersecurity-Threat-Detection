# Proof Plan — Portfolio Evidence Files

## Proof Images Required

| Filename | Source Plot | Where Captured | README Reference |
|----------|-------------|----------------|------------------|
| `01_dataset_preview.png` | `class_distribution.png` | `images/` | Dataset section |
| `02_preprocessing_output.png` | `correlation_heatmap.png` | `images/` | Preprocessing section |
| `03_training_logs.png` | `model_comparison_bar.png` | `images/` | Training section |
| `04_confusion_matrix.png` | `confusion_matrix_multiclass.png` | `images/` | Evaluation section |
| `05_anomaly_detection_graph.png` | `anomaly_score_distribution.png` | `images/` | Anomaly section |
| `06_prediction_results.png` | `roc_curves.png` | `images/` | ROC section |
| `07_api_test.png` | `feature_importance.png` | `images/` | API section |
| `08_final_output.png` | `attack_timeline.png` | `images/` | Simulation section |
| `09_github_repo.png` | Browser screenshot | Manual | README header |
| `10_readme_preview.png` | Browser screenshot | Manual | README header |

## How to Capture Screenshots 09 and 10

**09_github_repo.png:** After pushing to GitHub, take a full-page screenshot of your repository page
showing the file structure, README preview, and star/fork counts. Save to `images/09_github_repo.png`.

**10_readme_preview.png:** Take a screenshot of your GitHub README.md rendered in the browser
(the main repository page). Save to `images/10_readme_preview.png`.

## Automated Proof Generation

All images 01-08 are generated automatically by `run_all.py`. They are saved to:
- `outputs/plots/` — full-resolution PNG originals
- `images/` — copied with proof filenames

## Embedding in README.md

```markdown
## Proof & Results

![Dataset Distribution](images/01_dataset_preview.png)
![Confusion Matrix](images/04_confusion_matrix.png)
![ROC Curves](images/06_prediction_results.png)
![Anomaly Detection](images/05_anomaly_detection_graph.png)
![Attack Simulation](images/08_final_output.png)
```
