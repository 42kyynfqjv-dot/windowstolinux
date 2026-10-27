"""Compiler-time proof-domain experiment; no PE admission or code emission.
Run with the separately installed pinned z3-solver==4.15.4.0.
Expectations are instruction/API invariants, not derived from the production lifter.
"""
import json
import z3
assert z3.get_version_string() == '4.15.4'
results=[]
def obligation(name, assumptions, claim, expected, variables=(), limit=None):
    solver=z3.Solver();solver.set(timeout=2000)
    if limit is not None:solver.set(rlimit=limit)
    solver.add(*assumptions);solver.add(z3.Not(claim))
    status=solver.check()
    # Only unsat proves the universal implication. Unknown never authorizes use.
    assert str(status)==expected,(name,status,solver.reason_unknown())
    row=dict(name=name,result=str(status),proved=status==z3.unsat)
    if status==z3.sat:
        row['counterexample']={str(v):str(solver.model().eval(v,model_completion=True)) for v in variables}
    if status==z3.unknown:row['reason']=solver.reason_unknown()
    results.append(row)

n,i=z3.Ints('count index')
domain=[0<=n,n<=256,0<=i]
obligation('transform-entry',domain+[n>0,i==0],i<n,'unsat')
obligation('transform-step',domain+[i<n],z3.And(i+1<=n,i+1<=256),'unsat')
obligation('transform-backedge',domain+[i+1<n],z3.And(0<=i+1,i+1<n),'unsat')
# Bounds from a join independently permit a cross-product that the program guards exclude.
obligation('interval-only-join-is-insufficient',domain+[n>0,i<=256],i<n,'sat',(n,i))
count,sent,written=z3.BitVecs('count32 sent32 written32',32)
remaining=count-sent
safe=[z3.ULE(count,256),z3.ULE(sent,count),z3.UGT(written,0),z3.ULE(written,remaining)]
obligation('write-progress-no-wrap',safe,z3.And(z3.UGE(sent+written,sent),z3.ULE(sent+written,count),z3.ULT(count-(sent+written),remaining)),'unsat')
obligation('wrong-written-bound-rejected',[z3.ULE(count,256),z3.ULE(sent,count),z3.UGT(written,0),z3.ULE(written,count)],z3.ULE(sent+written,count),'sat',(count,sent,written))
old_epoch,new_epoch,old_length,new_length=z3.Ints('old_epoch new_epoch old_length new_length')
# Same buffer address is insufficient: current initialization is tied to this read.
obligation('stale-read-prefix-rejected',[0<=old_epoch,new_epoch>old_epoch,0<=new_length,new_length<=256,0<old_length,old_length<=256],new_length>0,'sat',(old_epoch,new_epoch,old_length,new_length))
active_epoch,cap_epoch,length,offset=z3.Ints('active_epoch capability_epoch initialized_length offset')
obligation('fresh-capability-access',[active_epoch==cap_epoch,0<=offset,offset<length,length<=256],z3.And(active_epoch==cap_epoch,0<=offset,offset<256),'unsat')
# A solver resource failure is a proof rejection, regardless of likely truth.
obligation('resource-exhaustion-rejects',safe,z3.And(z3.UGE(sent+written,sent),z3.ULE(sent+written,count)),'unknown',limit=1)
print(json.dumps(dict(solver=z3.get_version_string(),scope='standalone invariant obligations; not whole-program proof',results=results),indent=2))
