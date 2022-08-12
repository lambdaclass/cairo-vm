use crate::{
    any_box,
    vm::{
        errors::{exec_scope_errors::ExecScopeError, vm_errors::VirtualMachineError},
        hints::dict_manager::DictManager,
    },
};
use num_bigint::BigInt;
use std::{any::Any, collections::HashMap};

pub struct ExecutionScopes {
    pub data: Vec<HashMap<String, Box<dyn Any>>>,
}

pub struct ExecutionScopesProxy<'a> {
    scopes: &'a mut ExecutionScopes,
    current_scope: usize,
}

pub fn get_exec_scopes_proxy(exec_scopes: &mut ExecutionScopes) -> ExecutionScopesProxy {
    ExecutionScopesProxy {
        //Len will always be > 1 as execution scopes are always created with a main scope
        current_scope: exec_scopes.data.len() - 1,
        scopes: exec_scopes,
    }
}

impl ExecutionScopesProxy<'_> {
    pub fn enter_scope(&mut self, new_scope_locals: HashMap<String, Box<dyn Any>>) {
        self.scopes.enter_scope(new_scope_locals);
    }

    pub fn exit_scope(&mut self) -> Result<(), ExecScopeError> {
        self.scopes.exit_scope()
    }
    pub fn assign_or_update_variable(&mut self, var_name: &str, var_value: Box<dyn Any>) {
        if let Ok(local_variables) = self.get_local_variables_mut() {
            local_variables.insert(var_name.to_string(), var_value);
        }
    }

    pub fn delete_variable(&mut self, var_name: &str) {
        if let Ok(local_variables) = self.get_local_variables_mut() {
            local_variables.remove(var_name);
        }
    }
    pub fn get_local_variables_mut(
        &mut self,
    ) -> Result<&mut HashMap<String, Box<dyn Any>>, VirtualMachineError> {
        if self.scopes.data.len() > self.current_scope {
            return Ok(&mut self.scopes.data[self.current_scope]);
        }
        Err(VirtualMachineError::MainScopeError(
            ExecScopeError::NoScopeError,
        ))
    }

    pub fn get_local_variables(
        &self,
    ) -> Result<&HashMap<String, Box<dyn Any>>, VirtualMachineError> {
        if self.scopes.data.len() > self.current_scope {
            return Ok(&self.scopes.data[self.current_scope]);
        }
        Err(VirtualMachineError::MainScopeError(
            ExecScopeError::NoScopeError,
        ))
    }
    //Returns the value in the current execution scope that matches the name and is of type BigInt
    pub fn get_int(&self, name: &str) -> Result<BigInt, VirtualMachineError> {
        let mut val: Option<BigInt> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(int) = variable.downcast_ref::<BigInt>() {
                val = Some(int.clone());
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns the value in the current execution scope that matches the name
    pub fn get_any_boxed_ref(&self, name: &str) -> Result<&Box<dyn Any>, VirtualMachineError> {
        if let Some(variable) = self.get_local_variables()?.get(name) {
            return Ok(variable);
        }
        Err(VirtualMachineError::VariableNotInScopeError(
            name.to_string(),
        ))
    }

    //Returns the value in the current execution scope that matches the name
    pub fn get_any_boxed_mut(
        &mut self,
        name: &str,
    ) -> Result<&mut Box<dyn Any>, VirtualMachineError> {
        if let Some(variable) = self.get_local_variables_mut()?.get_mut(name) {
            return Ok(variable);
        }
        Err(VirtualMachineError::VariableNotInScopeError(
            name.to_string(),
        ))
    }

    //Returns a reference to the value in the current execution scope that matches the name and is of type BigInt
    pub fn get_int_ref(&self, name: &str) -> Result<&BigInt, VirtualMachineError> {
        let mut val: Option<&BigInt> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(int) = variable.downcast_ref::<BigInt>() {
                val = Some(int);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a mutable reference to the value in the current execution scope that matches the name and is of type BigInt
    pub fn get_mut_int_ref(&mut self, name: &str) -> Result<&mut BigInt, VirtualMachineError> {
        let mut val: Option<&mut BigInt> = None;
        if let Some(variable) = self.get_local_variables_mut()?.get_mut(name) {
            if let Some(int) = variable.downcast_mut::<BigInt>() {
                val = Some(int);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns the value in the current execution scope that matches the name and is of type List
    pub fn get_list(&self, name: &str) -> Result<Vec<BigInt>, VirtualMachineError> {
        let mut val: Option<Vec<BigInt>> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(list) = variable.downcast_ref::<Vec<BigInt>>() {
                val = Some(list.clone());
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a reference to the value in the current execution scope that matches the name and is of type List
    pub fn get_list_ref(&self, name: &str) -> Result<&Vec<BigInt>, VirtualMachineError> {
        let mut val: Option<&Vec<BigInt>> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(list) = variable.downcast_ref::<Vec<BigInt>>() {
                val = Some(list);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a mutable reference to the value in the current execution scope that matches the name and is of type List
    pub fn get_mut_list_ref(
        &mut self,
        name: &str,
    ) -> Result<&mut Vec<BigInt>, VirtualMachineError> {
        let mut val: Option<&mut Vec<BigInt>> = None;
        if let Some(variable) = self.get_local_variables_mut()?.get_mut(name) {
            if let Some(list) = variable.downcast_mut::<Vec<BigInt>>() {
                val = Some(list);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }

    //Returns the value in the current execution scope that matches the name and is of type ListU64
    pub fn get_listu64(&self, name: &str) -> Result<Vec<u64>, VirtualMachineError> {
        let mut val: Option<Vec<u64>> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(list) = variable.downcast_ref::<Vec<u64>>() {
                val = Some(list.clone());
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a reference to the value in the current execution scope that matches the name and is of type ListU64
    pub fn get_listu64_ref(&self, name: &str) -> Result<&Vec<u64>, VirtualMachineError> {
        let mut val: Option<&Vec<u64>> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(list) = variable.downcast_ref::<Vec<u64>>() {
                val = Some(list);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a mutable reference to the value in the current execution scope that matches the name and is of type ListU64
    pub fn get_mut_listu64_ref(
        &mut self,
        name: &str,
    ) -> Result<&mut Vec<u64>, VirtualMachineError> {
        let mut val: Option<&mut Vec<u64>> = None;
        if let Some(variable) = self.get_local_variables_mut()?.get_mut(name) {
            if let Some(list) = variable.downcast_mut::<Vec<u64>>() {
                val = Some(list);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }

    //Returns the value in the current execution scope that matches the name and is of type ListU64
    pub fn get_u64(&self, name: &str) -> Result<u64, VirtualMachineError> {
        let mut val: Option<u64> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(num) = variable.downcast_ref::<u64>() {
                val = Some(*num);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a reference to the value in the current execution scope that matches the name and is of type U64
    pub fn get_u64_ref(&self, name: &str) -> Result<&u64, VirtualMachineError> {
        let mut val: Option<&u64> = None;
        if let Some(variable) = self.get_local_variables()?.get(name) {
            if let Some(num) = variable.downcast_ref::<u64>() {
                val = Some(num);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }
    //Returns a mutable reference to the value in the current execution scope that matches the name and is of type U64
    pub fn get_mut_u64_ref(&mut self, name: &str) -> Result<&mut u64, VirtualMachineError> {
        let mut val: Option<&mut u64> = None;
        if let Some(variable) = self.get_local_variables_mut()?.get_mut(name) {
            if let Some(num) = variable.downcast_mut::<u64>() {
                val = Some(num);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }

    //Returns the value in the dict manager
    pub fn get_dict_manager_copy(&self) -> Result<DictManager, VirtualMachineError> {
        let mut val: Option<DictManager> = None;
        if let Some(variable) = self.get_local_variables()?.get("dict_manager") {
            if let Some(dict_manager) = variable.downcast_ref::<DictManager>() {
                val = Some(dict_manager.clone());
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError("dict_manager".to_string()))
    }

    //Returns a reference to the value in the dict manager
    pub fn get_dict_manager_ref(&self) -> Result<&DictManager, VirtualMachineError> {
        let mut val: Option<&DictManager> = None;
        if let Some(variable) = self.get_local_variables()?.get("dict_manager") {
            if let Some(dict_manager) = variable.downcast_ref::<DictManager>() {
                val = Some(dict_manager);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError("dict_manager".to_string()))
    }
    //Returns a mutable reference to the dict manager
    pub fn get_dict_manager_mut(&mut self) -> Result<&mut DictManager, VirtualMachineError> {
        let mut val: Option<&mut DictManager> = None;
        if let Some(variable) = self.get_local_variables_mut()?.get_mut("dict_manager") {
            if let Some(dict_manager) = variable.downcast_mut::<DictManager>() {
                val = Some(dict_manager);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError("dict_manager".to_string()))
    }

    //Returns a mutable reference to the value in the current execution scope that matches the name and is of type DictBigIntListU64
    pub fn get_mut_dict_int_list_u64_ref(
        &mut self,
        name: &str,
    ) -> Result<&mut HashMap<BigInt, Vec<u64>>, VirtualMachineError> {
        let mut val: Option<&mut HashMap<BigInt, Vec<u64>>> = None;
        if let Some(variable) = self.get_local_variables_mut()?.get_mut(name) {
            if let Some(dict) = variable.downcast_mut::<HashMap<BigInt, Vec<u64>>>() {
                val = Some(dict);
            }
        }
        val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
    }

    //Inserts the boxed value in scope
    pub fn insert_box(&mut self, name: &str, value: Box<dyn Any>) {
        self.assign_or_update_variable(name, value);
    }
    //Inserts the value in scope
    pub fn insert_value<T: 'static>(&mut self, name: &str, value: T) {
        self.assign_or_update_variable(name, any_box!(value));
    }
}

impl ExecutionScopes {
    pub fn new() -> ExecutionScopes {
        ExecutionScopes {
            data: vec![HashMap::new()],
        }
    }

    pub fn enter_scope(&mut self, new_scope_locals: HashMap<String, Box<dyn Any>>) {
        self.data.push(new_scope_locals);
    }

    pub fn exit_scope(&mut self) -> Result<(), ExecScopeError> {
        if self.data.len() == 1 {
            return Err(ExecScopeError::ExitMainScopeError);
        }
        self.data.pop();

        Ok(())
    }

    pub fn get_local_variables_mut(&mut self) -> Option<&mut HashMap<String, Box<dyn Any>>> {
        self.data.last_mut()
    }

    pub fn get_local_variables(&self) -> Option<&HashMap<String, Box<dyn Any>>> {
        self.data.last()
    }

    pub fn assign_or_update_variable(&mut self, var_name: &str, var_value: Box<dyn Any>) {
        if let Some(local_variables) = self.get_local_variables_mut() {
            local_variables.insert(var_name.to_string(), var_value);
        }
    }

    pub fn delete_variable(&mut self, var_name: &str) {
        if let Some(local_variables) = self.get_local_variables_mut() {
            local_variables.remove(&var_name.to_string());
        }
    }
}

impl Default for ExecutionScopes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint;

    use super::*;

    #[test]
    fn initialize_execution_scopes() {
        let scopes = ExecutionScopes::new();
        assert_eq!(scopes.data.len(), 1);
    }

    #[test]
    fn get_local_variables_test() {
        let var_name = String::from("a");
        let var_value: Box<dyn Any> = Box::new(bigint!(2));

        let scope = HashMap::from([(var_name, var_value)]);

        let scopes = ExecutionScopes { data: vec![scope] };
        assert_eq!(scopes.get_local_variables().unwrap().len(), 1);
        assert_eq!(
            scopes
                .get_local_variables()
                .unwrap()
                .get("a")
                .unwrap()
                .downcast_ref::<BigInt>(),
            Some(&bigint!(2))
        );
    }

    #[test]
    fn enter_new_scope_test() {
        let var_name = String::from("a");
        let var_value: Box<dyn Any> = Box::new(bigint!(2));

        let new_scope = HashMap::from([(var_name, var_value)]);

        let mut scopes = ExecutionScopes {
            data: vec![HashMap::from([(
                String::from("b"),
                (Box::new(bigint!(1)) as Box<dyn Any>),
            )])],
        };

        assert_eq!(scopes.get_local_variables().unwrap().len(), 1);
        assert_eq!(
            scopes
                .get_local_variables()
                .unwrap()
                .get("b")
                .unwrap()
                .downcast_ref::<BigInt>(),
            Some(&bigint!(1))
        );

        scopes.enter_scope(new_scope);

        // check that variable `b` can't be accessed now
        assert!(scopes.get_local_variables().unwrap().get("b").is_none());

        assert_eq!(scopes.get_local_variables().unwrap().len(), 1);
        assert_eq!(
            scopes
                .get_local_variables()
                .unwrap()
                .get("a")
                .unwrap()
                .downcast_ref::<BigInt>(),
            Some(&bigint!(2))
        );
    }

    #[test]
    fn exit_scope_test() {
        let var_name = String::from("a");
        let var_value: Box<dyn Any> = Box::new(bigint!(2));

        let new_scope = HashMap::from([(var_name, var_value)]);

        // this initializes an empty main scope
        let mut scopes = ExecutionScopes::new();

        // enter one extra scope
        scopes.enter_scope(new_scope);

        assert_eq!(scopes.get_local_variables().unwrap().len(), 1);
        assert_eq!(
            scopes
                .get_local_variables()
                .unwrap()
                .get("a")
                .unwrap()
                .downcast_ref::<BigInt>(),
            Some(&bigint!(2))
        );

        // exit the current scope
        let exit_scope_result = scopes.exit_scope();

        assert!(exit_scope_result.is_ok());

        // assert that variable `a` is no longer available
        assert!(scopes.get_local_variables().unwrap().get("a").is_none());

        // assert that we recovered the older scope
        assert!(scopes.get_local_variables().unwrap().is_empty());
    }

    #[test]
    fn assign_local_variable_test() {
        let var_value: Box<dyn Any> = Box::new(bigint!(2));

        let mut scopes = ExecutionScopes::new();

        scopes.assign_or_update_variable("a", var_value);

        assert_eq!(scopes.get_local_variables().unwrap().len(), 1);
        assert_eq!(
            scopes
                .get_local_variables()
                .unwrap()
                .get("a")
                .unwrap()
                .downcast_ref::<BigInt>(),
            Some(&bigint!(2))
        );
    }

    #[test]
    fn re_assign_local_variable_test() {
        let var_name = String::from("a");
        let var_value: Box<dyn Any> = Box::new(bigint!(2));

        let scope = HashMap::from([(var_name, var_value)]);

        let mut scopes = ExecutionScopes { data: vec![scope] };

        let var_value_new: Box<dyn Any> = Box::new(bigint!(3));

        scopes.assign_or_update_variable("a", var_value_new);

        assert_eq!(scopes.get_local_variables().unwrap().len(), 1);
        assert_eq!(
            scopes
                .get_local_variables()
                .unwrap()
                .get("a")
                .unwrap()
                .downcast_ref::<BigInt>(),
            Some(&bigint!(3))
        );
    }

    #[test]
    fn delete_local_variable_test() {
        let var_name = String::from("a");
        let var_value: Box<dyn Any> = Box::new(bigint!(2));

        let scope = HashMap::from([(var_name, var_value)]);

        let mut scopes = ExecutionScopes { data: vec![scope] };

        assert!(scopes
            .get_local_variables()
            .unwrap()
            .contains_key(&String::from("a")));

        scopes.delete_variable("a");

        assert!(!scopes
            .get_local_variables()
            .unwrap()
            .contains_key(&String::from("a")));
    }

    #[test]
    fn exit_main_scope_gives_error_test() {
        let mut scopes = ExecutionScopes::new();

        assert!(scopes.exit_scope().is_err());
    }
}
