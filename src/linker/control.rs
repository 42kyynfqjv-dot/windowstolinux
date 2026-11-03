//! Shared bounded call/return graph validation. Success grants no memory,
//! exception, ABI or emission authority. Those remain separate proof obligations.
use std::collections::BTreeSet;

pub(super) enum Edge {
    Next(u32),
    Branch(u32, u32),
    Call { target: u32, next: u32 },
    Return,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Cycle,
    Budget,
    MissingTarget,
    RecursionOrDepth,
}
pub(super) fn validate(
    entry: u32,
    max_depth: usize,
    max_steps: usize,
    edge: impl Fn(u32) -> Option<Edge>,
) -> Result<(), Error> {
    let mut pending = vec![(entry, vec![entry], Vec::<u32>::new(), BTreeSet::new())];
    let mut steps = 0usize;
    while let Some((pc, mut targets, mut returns, mut seen)) = pending.pop() {
        if !seen.insert((pc, returns.clone())) {
            return Err(Error::Cycle);
        }
        if steps >= max_steps {
            return Err(Error::Budget);
        }
        steps += 1;
        match edge(pc).ok_or(Error::MissingTarget)? {
            Edge::Call { target, next } => {
                if targets.len() > max_depth || targets.contains(&target) {
                    return Err(Error::RecursionOrDepth);
                }
                targets.push(target);
                returns.push(next);
                pending.push((target, targets, returns, seen));
            }
            Edge::Return => {
                if let Some(next) = returns.pop() {
                    targets.pop();
                    pending.push((next, targets, returns, seen));
                }
            }
            Edge::Branch(target, next) => {
                pending.push((target, targets.clone(), returns.clone(), seen.clone()));
                pending.push((next, targets, returns, seen));
            }
            Edge::Next(next) => pending.push((next, targets, returns, seen)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_helper_returns_to_each_original_continuation() {
        // Two calls to one helper must retain different continuation contexts.
        let graph = |pc| match pc {
            0 => Some(Edge::Call {
                target: 10,
                next: 1,
            }),
            1 => Some(Edge::Call {
                target: 10,
                next: 2,
            }),
            2 | 10 => Some(Edge::Return),
            _ => None,
        };
        assert_eq!(validate(0, 1, 5, graph), Ok(()));
        assert_eq!(validate(0, 0, 5, graph), Err(Error::RecursionOrDepth));
        assert_eq!(validate(0, 1, 4, graph), Err(Error::Budget));
        assert_eq!(
            validate(0, 1, 5, |pc| if pc == 2 { None } else { graph(pc) }),
            Err(Error::MissingTarget)
        );
    }
    #[test]
    fn recursion_and_control_cycles_are_distinct_rejections() {
        assert_eq!(
            validate(0, 4, 20, |_| Some(Edge::Call { target: 0, next: 1 })),
            Err(Error::RecursionOrDepth)
        );
        assert_eq!(
            validate(0, 4, 20, |_| Some(Edge::Next(0))),
            Err(Error::Cycle)
        );
    }
}
