"""Keep synthetic/test scan evidence out of the operator's application state."""
import pytest

@pytest.fixture(autouse=True)
def private_ollama_results(request,tmp_path,monkeypatch):
    if request.path.name.startswith("test_ollama"):
        monkeypatch.setenv("REDVECTOR_RESULTS_DIR",str(tmp_path/"private-results"))
