// The five-minute proof: two people, one table.

// policy0 — alice administers everything in her tenant.
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };

// policy1 — bob, an analyst, reads EU orders only, with email masked.
@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
@column_mask("email")
permit(
  principal in Rustberg::Group::"analyst",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource
) when { resource.tenant == principal.tenant };
