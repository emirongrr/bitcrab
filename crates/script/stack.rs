//! Bitcoin Script Stack.
//!
//! Manages data elements pushed during script execution.

use bitcrab_common::types::constants::{MAX_SCRIPT_ELEMENT_SIZE, MAX_STACK_SIZE};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StackError {
    #[error("stack overflow: exceeds MAX_STACK_SIZE ({0})")]
    Overflow(usize),
    #[error("stack underflow: not enough elements")]
    Underflow,
    #[error("element too large: {0} bytes (max {1})")]
    ElementTooLarge(usize, usize),
}

pub struct ScriptStack {
    items: Vec<Vec<u8>>,
}

impl ScriptStack {
    pub fn new() -> Self {
        Self {
            items: Vec::with_capacity(32),
        }
    }

    /// Push a new element onto the stack.
    pub fn push(&mut self, item: Vec<u8>) -> Result<(), StackError> {
        if self.items.len() >= MAX_STACK_SIZE {
            return Err(StackError::Overflow(MAX_STACK_SIZE));
        }
        if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(StackError::ElementTooLarge(item.len(), MAX_SCRIPT_ELEMENT_SIZE));
        }
        self.items.push(item);
        Ok(())
    }

    /// Pop the top element from the stack.
    pub fn pop(&mut self) -> Result<Vec<u8>, StackError> {
        self.items.pop().ok_or(StackError::Underflow)
    }

    /// Peek at the top element.
    pub fn top(&self) -> Result<&Vec<u8>, StackError> {
        self.items.last().ok_or(StackError::Underflow)
    }

    /// Duplicate the top element.
    pub fn dup(&mut self) -> Result<(), StackError> {
        let top = self.top()?.clone();
        self.push(top)
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
