defmodule Xpublic_key do
require Record
  Record.defrecord :"SubjectPublicKeyInfoAlgorithm", [algorithm: :undefined, parameters: :asn1_NOVALUE]
  Record.defrecord :"path_validation_state", [valid_policy_tree: :undefined, explicit_policy: :undefined, inhibit_any_policy: :undefined, policy_mapping: :undefined, cert_num: :undefined, last_cert: false, permitted_subtrees: :no_constraints, excluded_subtrees: [], working_public_key_algorithm: :undefined, working_public_key: :undefined, working_public_key_parameters: :undefined, working_issuer_name: :undefined, max_path_length: :undefined, verify_fun: :undefined, user_state: :undefined]
  Record.defrecord :"policy_tree_node", [valid_policy: :undefined, qualifier_set: :undefined, criticality_indicator: :undefined, expected_policy_set: :undefined]
  Record.defrecord :"revoke_state", [reasons_mask: :undefined, cert_status: :undefined, interim_reasons_mask: :undefined, valid_ext: :undefined]
  Record.defrecord :"ECPoint", [point: :undefined]
end
