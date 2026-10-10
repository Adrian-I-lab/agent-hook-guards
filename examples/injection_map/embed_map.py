#!/usr/bin/env python3
"""Embed the injection corpus with a local Ollama model and map it to 2D.

Example, not a guard. It needs numpy, scikit-learn, and matplotlib, and
umap-learn for --method umap. The guards themselves stay standard library.

    python3 examples/injection_map/embed_map.py --method pca
    .venv/bin/python examples/injection_map/embed_map.py --method umap

Steps:

1. Embed every corpus item through the Ollama embeddings API on localhost.
   Vectors are cached in out/, keyed by model and text hash, so a rerun makes
   no request for text it has already embedded.
2. Standardise each dimension (zero mean, unit variance).
3. PCA to --pca-components dimensions, and print the variance explained.
4. Reduce to 2D: the first two principal components (--method pca), or UMAP
   on the PCA scores with a fixed random_state (--method umap).
5. Plot two panels, coloured by label and by technique, and write the PNG, a
   CSV of the 2D coordinates (the table view of the figure), and a JSON
   summary of parameters, versions, and scores to out/.

Only localhost addresses are accepted for --ollama-url. Everything in out/ is
a generated result and is ignored by git.
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, REPO)

from agent_hook_guards import injection_corpus as ic  # noqa: E402

LOCAL_HOSTS = frozenset(["localhost", "127.0.0.1", "::1"])
DEFAULT_OUT = os.path.join(HERE, "out")
# Reference categorical palette, slots 1 to 7, checked for colour-vision
# deficiency separation. Order is fixed and follows ic.TECHNIQUES.
TECHNIQUE_COLOURS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7"]
LABEL_COLOURS = {"injection": "#2a78d6", "benign": "#eb6834"}
LABEL_MARKERS = {"injection": "o", "benign": "X"}


def die(message, code=2):
    sys.stderr.write("embed_map: {}\n".format(message))
    sys.exit(code)


def check_local(url):
    host = urllib.parse.urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        die("refusing --ollama-url {}: only localhost is allowed".format(url))


def post_json(url, payload, timeout=120):
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def model_digest(base, model):
    with urllib.request.urlopen(base.rstrip("/") + "/api/tags", timeout=30) as response:
        tags = json.loads(response.read().decode("utf-8"))
    for entry in tags.get("models", []):
        if entry.get("name") in (model, model + ":latest"):
            return entry.get("digest")
    die("model {} is not available in the local Ollama".format(model))


def embed(texts, base, model, prefix, cache_path, batch):
    cache = {}
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as handle:
            cache = json.load(handle)
    keys = [hashlib.sha256((model + "\0" + prefix + text).encode("utf-8")).hexdigest()
            for text in texts]
    todo = [i for i, key in enumerate(keys) if key not in cache]
    for start in range(0, len(todo), batch):
        chunk = todo[start:start + batch]
        reply = post_json(base.rstrip("/") + "/api/embed",
                          {"model": model, "input": [prefix + texts[i] for i in chunk]})
        vectors = reply.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(chunk):
            die("unexpected reply from /api/embed")
        for i, vector in zip(chunk, vectors):
            cache[keys[i]] = vector
    if todo:
        with open(cache_path, "w", encoding="utf-8") as handle:
            json.dump(cache, handle)
    return [cache[key] for key in keys], len(todo)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--method", choices=("pca", "umap"), default="umap")
    parser.add_argument("--corpus", default=os.path.join(REPO, "corpus", "injection"))
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="nomic-embed-text")
    parser.add_argument("--prefix", default="clustering: ",
                        help="task prefix that nomic-embed-text expects; '' for none")
    parser.add_argument("--pca-components", type=int, default=20)
    parser.add_argument("--n-neighbors", type=int, default=15)
    parser.add_argument("--min-dist", type=float, default=0.1)
    parser.add_argument("--metric", default="euclidean")
    parser.add_argument("--random-state", type=int, default=20261010)
    parser.add_argument("--batch", type=int, default=32)
    args = parser.parse_args(argv)

    check_local(args.ollama_url)
    if args.method == "umap":
        try:
            import umap  # noqa: F401
        except ImportError:
            die("--method umap needs umap-learn, which this interpreter ({}) cannot import. "
                "Use an environment that has it, or run --method pca.".format(sys.executable))

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    import sklearn
    from sklearn.decomposition import PCA
    from sklearn.metrics import silhouette_score
    from sklearn.preprocessing import StandardScaler

    items = ic.load(args.corpus)
    problems = ic.validate_items(items)
    if problems:
        die("corpus is invalid: {}".format(problems[0]))
    os.makedirs(args.out, exist_ok=True)
    digest = model_digest(args.ollama_url, args.model)
    cache_path = os.path.join(args.out, "embeddings-{}.json".format(args.model.replace(":", "_")))
    vectors, fetched = embed([i["text"] for i in items], args.ollama_url, args.model,
                             args.prefix, cache_path, args.batch)
    X = np.asarray(vectors, dtype=float)
    print("embedded {} items with {} (digest {}), dim={}, fetched={}, cached={}".format(
        len(items), args.model, (digest or "?")[:12], X.shape[1], fetched, len(items) - fetched))

    Z = StandardScaler().fit_transform(X)
    k = min(args.pca_components, Z.shape[0] - 1, Z.shape[1])
    pca = PCA(n_components=k, svd_solver="full", random_state=args.random_state)
    scores = pca.fit_transform(Z)
    ratio = pca.explained_variance_ratio_
    print("PCA variance explained: PC1={:.4f} PC2={:.4f} PC1+PC2={:.4f} first {} PCs={:.4f}".format(
        ratio[0], ratio[1], ratio[0] + ratio[1], k, ratio.sum()))

    params = {"pca_components": k}
    if args.method == "pca":
        coords = scores[:, :2]
        axis = ("PC1 ({:.1%} of variance)".format(ratio[0]),
                "PC2 ({:.1%} of variance)".format(ratio[1]))
    else:
        import umap
        reducer = umap.UMAP(n_components=2, n_neighbors=args.n_neighbors, min_dist=args.min_dist,
                            metric=args.metric, random_state=args.random_state)
        coords = reducer.fit_transform(scores)
        params.update({"n_neighbors": args.n_neighbors, "min_dist": args.min_dist,
                       "metric": args.metric, "random_state": args.random_state,
                       "umap_learn": umap.__version__})
        print("UMAP n_neighbors={} min_dist={} metric={} random_state={} input=PCA{}".format(
            args.n_neighbors, args.min_dist, args.metric, args.random_state, k))
        axis = ("UMAP 1", "UMAP 2")

    labels = np.array([i["label"] for i in items])
    techniques = np.array([i["technique"] for i in items])
    sil_pca = float(silhouette_score(scores, labels))
    sil_2d = float(silhouette_score(coords, labels))
    print("silhouette of injection vs benign: PCA{} space={:.4f}, 2D {}={:.4f}".format(
        k, sil_pca, args.method, sil_2d))

    fig, panels = plt.subplots(1, 2, figsize=(13, 5.8), constrained_layout=True)
    for label in ("injection", "benign"):
        mask = labels == label
        panels[0].scatter(coords[mask, 0], coords[mask, 1], s=36, c=LABEL_COLOURS[label],
                          marker=LABEL_MARKERS[label], edgecolors="white", linewidths=0.6,
                          alpha=0.9, label="{} (n={})".format(label, int(mask.sum())))
    panels[0].set_title("By label")
    for colour, tech in zip(TECHNIQUE_COLOURS, ic.TECHNIQUES):
        for label in ("injection", "benign"):
            mask = (techniques == tech) & (labels == label)
            panels[1].scatter(coords[mask, 0], coords[mask, 1], s=36, c=colour,
                              marker=LABEL_MARKERS[label], edgecolors="white", linewidths=0.6,
                              alpha=0.9, label=tech if label == "injection" else None)
    panels[1].set_title("By technique (circle = injection, cross = benign lookalike)")
    for ax in panels:
        ax.set_xlabel(axis[0])
        ax.set_ylabel(axis[1])
        ax.grid(True, color="#e6e6e3", linewidth=0.6)
        ax.set_axisbelow(True)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        ax.legend(frameon=False, fontsize=8, loc="best")
    fig.suptitle("Synthetic injection corpus, {} items, {} embeddings, {}".format(
        len(items), args.model, args.method.upper()))
    png = os.path.join(args.out, "injection_map_{}.png".format(args.method))
    fig.savefig(png, dpi=200)
    plt.close(fig)

    with open(os.path.join(args.out, "injection_map_{}.csv".format(args.method)), "w",
              newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "label", "technique", "channel", "x", "y"])
        for item, (x, y) in zip(items, coords):
            writer.writerow([item["id"], item["label"], item["technique"], item["channel"],
                             "{:.5f}".format(x), "{:.5f}".format(y)])
    summary = {
        "method": args.method, "items": len(items), "model": args.model, "model_digest": digest,
        "prefix": args.prefix, "params": params,
        "pca_variance_ratio": [round(float(v), 6) for v in ratio],
        "silhouette_label_pca": round(sil_pca, 6), "silhouette_label_2d": round(sil_2d, 6),
        "versions": {"python": platform.python_version(), "numpy": np.__version__,
                     "scikit-learn": sklearn.__version__, "matplotlib": matplotlib.__version__},
    }
    with open(os.path.join(args.out, "injection_map_{}.json".format(args.method)), "w",
              encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1)
    print("wrote {}".format(os.path.relpath(png, REPO)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
