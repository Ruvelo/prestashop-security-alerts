<section id="ruvelo-security-alerts" class="panel widget">
  <div class="panel-heading">
    <i class="icon-shield"></i> {l s='Security alerts' d='Modules.Ruvelosecurityalerts.Admin'}
  </div>
  <section class="dash_security_alerts">
    {if $ruvelo_sa_last === null}
      <p>{l s='No check has run yet.' d='Modules.Ruvelosecurityalerts.Admin'}</p>
    {elseif $ruvelo_sa_total == 0}
      <p>
        <strong>{l s='No known vulnerabilities in what was checked.' d='Modules.Ruvelosecurityalerts.Admin'}</strong>
        {if $ruvelo_sa_incomplete}<br>{l s='Part of the check could not run. See the page for details.' d='Modules.Ruvelosecurityalerts.Admin'}{/if}
      </p>
    {else}
      <p>
        {if $ruvelo_sa_exploited > 0}
          <span class="label label-danger" style="font-size:1.1em">{$ruvelo_sa_exploited|intval} {l s='exploited in the wild' d='Modules.Ruvelosecurityalerts.Admin'}</span>
        {/if}
        <span class="label label-warning" style="font-size:1.1em">{$ruvelo_sa_other|intval} {l s='other' d='Modules.Ruvelosecurityalerts.Admin'}</span>
      </p>
    {/if}
    <p>
      <a class="btn btn-default" href="{$ruvelo_sa_url|escape:'html':'UTF-8'}">{l s='View security alerts' d='Modules.Ruvelosecurityalerts.Admin'}</a>
      {if $ruvelo_sa_last !== null}<small class="text-muted">{l s='Last check' d='Modules.Ruvelosecurityalerts.Admin'}: {$ruvelo_sa_last|escape:'html':'UTF-8'} UTC</small>{/if}
    </p>
  </section>
</section>
