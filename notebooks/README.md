# Hunting Notebooks

Roadmap F68. Three notebooks that walk through hunts with CyberPulse's own library, on
synthetic data only (seeded benign baseline plus the lab attack chain):

| Notebook | Hunt |
| :--- | :--- |
| `01_stack_counting.ipynb` | Stack every process, read the long tail, pivot on tail values |
| `02_pivot_and_timeline.ipynb` | Pivot from one host to the whole intrusion and its timeline |
| `03_rare_parent_child.ipynb` | Score parent-child process pairs against a baseline |

They need nothing beyond the project's requirements plus Jupyter
(`pip install jupyterlab`, then `CYBERPULSE_LAB_MODE=true jupyter lab notebooks/`).
No outputs are stored in the repository; `tests/test_notebooks.py` executes every code cell
so the notebooks keep working as the code changes. To hunt real data, replace the setup
cell with events exported from your SIEM, and keep those exports out of the repository.
