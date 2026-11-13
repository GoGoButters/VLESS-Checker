"""A node in several groups tests one chunk of each group in turn."""
import asyncio
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _node_module():
    sys.path.insert(0, os.path.join(ROOT, "node"))
    try:
        spec = importlib.util.spec_from_file_location("node_main_rr", os.path.join(ROOT, "node", "main.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(os.path.join(ROOT, "node"))


class FakeWorker:
    """Worker with the panel and the checks replaced by an in-memory log."""

    def __init__(self, mod, lists):
        self.w = mod.Worker()
        self.w.master = "http://127.0.0.1"
        self.lists = lists          # gid -> list of urls
        self.order = []
        self.finished = set()   # the panel stops listing a group as due once it is complete

        async def start_run(job):
            urls = self.lists[job["group_id"]]
            size = job["chunk_size"]
            return mod.GroupRun(job, [urls[i:i + size] for i in range(0, len(urls), size)])

        async def run_chunk(run, test_urls, speed_url):
            self.order.append((run.job["group_id"], run.next + 1))
            run.next += 1
            if run.next >= len(run.chunks):
                self.finished.add(run.job["group_id"])
                return True
            return False

        self.w.start_run = start_run
        self.w.run_chunk = run_chunk


def _jobs(*specs):
    return {"jobs": [{"group_id": g, "name": f"g{g}", "generation": gen, "due": True, "chunk_size": 2}
                     for g, gen in specs], "test_urls": []}


def test_chunks_alternate_between_groups():
    mod = _node_module()
    fw = FakeWorker(mod, {1: list("abcdef"), 2: list("wxyz")})
    runs = {}

    async def go():
        for _ in range(3):
            await fw.w.step(_jobs(*[(g, gen) for g, gen in ((1, "a.0"), (2, "b.0")) if g not in fw.finished]), runs)
    asyncio.run(go())
    assert fw.order == [(1, 1), (2, 1), (1, 2), (2, 2), (1, 3)]
    assert runs == {}


def test_new_generation_replaces_a_run_in_progress():
    mod = _node_module()
    fw = FakeWorker(mod, {1: list("abcdef")})
    runs = {}

    async def go():
        await fw.w.step(_jobs((1, "a.0")), runs)            # chunk 1 of the old generation
        await fw.w.step(_jobs((1, "a.1")), runs)            # panel bumped the generation
    asyncio.run(go())
    assert fw.order == [(1, 1), (1, 1)]
    assert runs[1].job["generation"] == "a.1"


def test_group_no_longer_due_is_dropped():
    mod = _node_module()
    fw = FakeWorker(mod, {1: list("abcdef"), 2: list("wxyz")})
    runs = {}

    async def go():
        await fw.w.step(_jobs((1, "a.0"), (2, "b.0")), runs)
        await fw.w.step(_jobs((2, "b.0")), runs)            # node removed from group 1
    asyncio.run(go())
    assert fw.order == [(1, 1), (2, 1), (2, 2)]
    assert 1 not in runs
